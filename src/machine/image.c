/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-bus.h"

#include "discover-image.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hashmap.h"
#include "image.h"
#include "io-util.h"
#include "log.h"
#include "machined.h"
#include "operation.h"
#include "process-util.h"
#include "recurse-dir.h"
#include "set.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "tmpfile-util.h"

int clean_pool_read_first_entry(FILE *file, int child_error, sd_bus_error *error) {
        _cleanup_free_ char *name = NULL;
        bool success;
        int r;

        assert(file);

        if (fseek(file, 0, SEEK_SET) < 0)
                return log_debug_errno(errno, "Failed to seek to the beginning of tmp file: %m");

        /* The resulting temporary file starts with a boolean value that indicates success or not. */
        errno = 0;
        size_t n = fread(&success, 1, sizeof(success), file);
        if (n != sizeof(success)) {
                log_debug_errno(errno_or_else(EIO), "Received unexpected amount of %zu bytes: %m", n);
                return child_error < 0 ? child_error : errno_or_else(EIO);
        }

        if (child_error < 0) {
                /* The clean-up operation failed. In this case the resulting temporary file should contain a boolean
                 * set to false followed by the name of the failed image. Let's try to read this and use it for the
                 * error message. If we can't read it, don't mind, and return the naked error. */

                if (success) { /* The resulting temporary file could not be updated, ignore it. */
                        log_debug("Child process exited with an error. We expected a name of the image which caused the failure in the tmp file, but it failed as well.");
                        return child_error;
                }

                r = read_nul_string(file, LONG_LINE_MAX, &name);
                if (r <= 0) { /* Same here... */
                        log_debug_errno(r, "Failed to read nul-terminated string from tmp file: %m");
                        return child_error;
                }

                log_debug_errno(child_error, "Failed to remove image '%s': %m", name);
                return sd_bus_error_set_errnof(error, child_error, "Failed to remove image '%s': %m", name);
        }

        if (!success)
                return log_debug_errno(SYNTHETIC_ERRNO(ESTALE), "Inconsistent state of the temporary file.");

        return 0;
}

int clean_pool_read_next_entry(FILE *file, char **ret_name, uint64_t *ret_usage) {
        /* Return value:
         * r < 0: error
         * r == 0 last record returned
         * r > 0 more records expected */

        _cleanup_free_ char *name = NULL;
        uint64_t usage;
        int r;

        assert(file);

        r = read_nul_string(file, LONG_LINE_MAX, &name);
        if (r < 0)
                return log_debug_errno(r, "Failed to read nul-terminated string: %m");
        if (r == 0) /* reached the end */
                return 0;

        errno = 0;
        size_t n = fread(&usage, 1, sizeof(usage), file);
        if (n != sizeof(usage))
                return log_debug_errno(errno_or_else(EIO), "Received unexpected amount of %zu bytes: %m", n);

        if (ret_name)
                *ret_name = TAKE_PTR(name);
        if (ret_usage)
                *ret_usage = usage;

        return 1;
}

static int inodes_add(Set **inodes, int dir_fd, const char *name) {
        int r;

        assert(inodes);
        assert(dir_fd >= 0);
        assert(name);

        _cleanup_free_ struct stat *st = new(struct stat, 1);
        if (!st)
                return -ENOMEM;

        if (fstatat(dir_fd, name, st, /* flags= */ 0) < 0) {
                /* E.g. a dangling symlink, which refers to no image */
                log_debug_errno(errno, "Failed to stat '%s', ignoring: %m", name);
                return 0;
        }

        r = set_ensure_consume(inodes, &inode_hash_ops, TAKE_PTR(st));
        if (r < 0)
                return r;

        return 0;
}

static int mstack_collect_inodes(Image *image, Set **inodes) {
        int r;

        assert(image);
        assert(image->type == IMAGE_MSTACK);
        assert(inodes);

        /* Collects the inodes that the entries of an .mstack image refer to, including all versions in .v/
         * directories. Its layers are typically symlinks to hidden images in the same pool (as importd
         * creates them for OCI images), which hence are still in use. */

        _cleanup_close_ int dir_fd = open(image->path, O_DIRECTORY|O_CLOEXEC);
        if (dir_fd < 0)
                return -errno;

        _cleanup_free_ DirectoryEntries *de = NULL;
        r = readdir_all(dir_fd, RECURSE_DIR_IGNORE_DOT, &de);
        if (r < 0)
                return r;

        FOREACH_ARRAY(i, de->entries, de->n_entries) {
                const char *fname = (*i)->d_name;

                r = inodes_add(inodes, dir_fd, fname);
                if (r < 0)
                        return r;

                if (!endswith(fname, ".v"))
                        continue;

                _cleanup_free_ DirectoryEntries *vde = NULL;
                _cleanup_close_ int v_fd = openat(dir_fd, fname, O_DIRECTORY|O_CLOEXEC);
                if (v_fd < 0) {
                        log_debug_errno(errno, "Failed to open '%s/%s', ignoring: %m", image->path, fname);
                        continue;
                }

                r = readdir_all(v_fd, RECURSE_DIR_IGNORE_DOT, &vde);
                if (r < 0)
                        return r;

                FOREACH_ARRAY(j, vde->entries, vde->n_entries) {
                        r = inodes_add(inodes, v_fd, (*j)->d_name);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int image_is_used_by_mstack(Image *image, Set *inodes) {
        struct stat st;

        assert(image);

        if (set_isempty(inodes))
                return false;

        if (stat(image->path, &st) < 0)
                return -errno;

        return set_contains(inodes, &st);
}

/* Runs in the (sd-clean) child, and exits it on failure. inodes are those used by .mstack images. */
static void clean_pool_one(
                Manager *manager,
                ImageCleanPoolMode mode,
                Image *image,
                Set *inodes,
                int result_fd,
                int errno_fd) {

        ssize_t n;
        int r;

        assert(manager);
        assert(image);
        assert(result_fd >= 0);
        assert(errno_fd >= 0);

        /* We can't remove vendor images (i.e. those in /usr) */
        if (image_is_vendor(image))
                return;
        if (image_is_host(image))
                return;
        if (mode == IMAGE_CLEAN_POOL_REMOVE_HIDDEN && !image_is_hidden(image))
                return;

        r = image_is_used_by_mstack(image, inodes);
        if (r < 0) {
                log_debug_errno(r, "Failed to check whether image '%s' is used by an .mstack image: %m", image->name);
                report_errno_and_exit(errno_fd, r);
        }
        if (r > 0) {
                log_debug("Keeping image '%s' because an .mstack image uses it.", image->name);
                return;
        }

        r = image_remove(image, manager->runtime_scope);
        if (r == -EBUSY) {
                log_debug("Keeping image '%s' because it's currently used.", image->name);
                return;
        }
        if (r < 0) {
                bool success = false;

                log_debug_errno(r, "Failed to remove image '%s': %m", image->name);

                /* If the operation failed, let's override everything we wrote, and instead write there at which image we failed. */
                if (ftruncate(result_fd, 0) < 0 ||
                    lseek(result_fd, 0, SEEK_SET) < 0 ||
                    write(result_fd, &success, sizeof(success)) < 0 ||
                    write(result_fd, image->name, strlen(image->name)+1) < 0)
                        log_debug_errno(errno, "Failed to truncate, rewind, or write to tmp file, ignoring: %m");

                /* Report original error code (not results of rewind/truncate/etc */
                report_errno_and_exit(errno_fd, r);
        }

        n = loop_write(result_fd, image->name, strlen(image->name) + 1);
        if (n < 0) {
                log_debug_errno(n, "Failed to write image name to tmp file: %m");
                report_errno_and_exit(errno_fd, n);
        }

        n = loop_write(result_fd, &image->usage_exclusive, sizeof(image->usage_exclusive));
        if (n < 0) {
                log_debug_errno(n, "Failed to write image's usage to tmp file: %m");
                report_errno_and_exit(errno_fd, n);
        }
}

int image_clean_pool_operation(Manager *manager, ImageCleanPoolMode mode, Operation **ret_operation) {
        _cleanup_close_pair_ int errno_pipe_fd[2] = EBADF_PAIR;
        _cleanup_close_ int result_fd = -EBADF;
        _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
        int r;

        assert(manager);
        assert(ret_operation);

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                return log_debug_errno(errno, "Failed to create pipe: %m");

        /* Create a temporary file we can dump information about deleted images into. We use a temporary file for this
         * instead of a pipe or so, since this might grow quit large in theory and we don't want to process this
         * continuously */
        result_fd = open_tmpfile_unlinkable(NULL, O_RDWR|O_CLOEXEC);
        if (result_fd < 0)
                return log_debug_errno(result_fd, "Failed to open tmpfile: %m");

        /* This might be a slow operation, run it asynchronously in a background process */
        r = pidref_safe_fork("(sd-clean)", FORK_RESET_SIGNALS, &child);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork(): %m");
        if (r == 0) {
                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                _cleanup_hashmap_free_ Hashmap *images = NULL;
                r = image_discover(manager->runtime_scope, IMAGE_MACHINE, /* root= */ NULL, &images);
                if (r < 0) {
                        log_debug_errno(r, "Failed to discover images: %m");
                        report_errno_and_exit(errno_pipe_fd[1], r);
                }

                bool success = true;
                ssize_t n = loop_write(result_fd, &success, sizeof(success));
                if (n < 0) {
                        log_debug_errno(n, "Failed to write to tmp file: %m");
                        report_errno_and_exit(errno_pipe_fd[1], n);
                }

                /* Remove .mstack images first, since with mode=all, their layers are only unused once they
                 * are gone. Then remove everything else that the remaining .mstack images don't use. */
                Image *image;
                HASHMAP_FOREACH(image, images)
                        if (image->type == IMAGE_MSTACK)
                                clean_pool_one(manager, mode, image, /* inodes= */ NULL, result_fd, errno_pipe_fd[1]);

                _cleanup_set_free_ Set *inodes = NULL;
                HASHMAP_FOREACH(image, images) {
                        if (image->type != IMAGE_MSTACK)
                                continue;

                        r = mstack_collect_inodes(image, &inodes);
                        if (r == -ENOENT) /* Just removed */
                                continue;
                        if (r < 0) {
                                log_debug_errno(r, "Failed to determine layers of image '%s': %m", image->name);
                                report_errno_and_exit(errno_pipe_fd[1], r);
                        }
                }

                HASHMAP_FOREACH(image, images)
                        if (image->type != IMAGE_MSTACK)
                                clean_pool_one(manager, mode, image, inodes, result_fd, errno_pipe_fd[1]);

                result_fd = safe_close(result_fd);
                _exit(EXIT_SUCCESS);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        /* The clean-up might take a while, hence install a watch on the child and return */
        r = operation_new(manager, /* machine= */ NULL, &child, errno_pipe_fd[0], ret_operation);
        if (r < 0)
                 return r;

        (*ret_operation)->extra_fd = TAKE_FD(result_fd);
        TAKE_FD(errno_pipe_fd[0]);
        TAKE_PIDREF(child);
        return 0;
}

static const char* const image_clean_pool_mode_table[_IMAGE_CLEAN_POOL_MAX] = {
        [IMAGE_CLEAN_POOL_REMOVE_ALL]    = "all",
        [IMAGE_CLEAN_POOL_REMOVE_HIDDEN] = "hidden"
};

DEFINE_STRING_TABLE_LOOKUP(image_clean_pool_mode, ImageCleanPoolMode);
