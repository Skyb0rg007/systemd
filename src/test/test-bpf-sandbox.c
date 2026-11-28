/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sched.h>
#include <linux/sched.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "bpf-sandbox.h"
#include "bpf-util.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "manager.h"
#include "nsflags.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "rm-rf.h"
#include "serialize.h"
#include "tests.h"
#include "tmpfile-util.h"

static int try_clone3(uint64_t flags) {
        struct clone_args args = {
                .flags = flags,
                .exit_signal = SIGCHLD,
        };
        pid_t pid;

        pid = (pid_t) syscall(__NR_clone3, &args, sizeof(args));
        if (pid < 0)
                return -errno;
        if (pid == 0)
                _exit(EXIT_SUCCESS);

        ASSERT_OK(pidref_wait_for_terminate_and_check("(clone3)", &PIDREF_MAKE_FROM_PID(pid), /* flags= */ 0));
        return 0;
}

static int try_clone(unsigned long flags) {
        pid_t pid;

        /* On s390 the first two arguments are swapped, with a NULL stack both orders work the same. */
        pid = (pid_t) syscall(__NR_clone, flags | SIGCHLD, NULL, NULL, NULL, NULL);
        if (pid < 0)
                return -errno;
        if (pid == 0)
                _exit(EXIT_SUCCESS);

        ASSERT_OK(pidref_wait_for_terminate_and_check("(clone)", &PIDREF_MAKE_FROM_PID(pid), /* flags= */ 0));
        return 0;
}

static int try_openat2(const char *dir, const char *name, mode_t mode) {
        struct open_how how = {
                .flags = O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,
                .mode = mode,
        };
        _cleanup_free_ char *p = NULL;
        int fd;

        ASSERT_NOT_NULL(p = path_join(dir, name));

        fd = openat2(AT_FDCWD, p, &how, sizeof(how));
        if (fd < 0)
                return -errno;

        safe_close(fd);
        ASSERT_OK_ERRNO(unlink(p));
        return 0;
}

static int try_tmpfile(const char *dir, mode_t mode) {
        _cleanup_close_ int fd = -EBADF;

        fd = open(dir, O_TMPFILE|O_WRONLY|O_CLOEXEC, mode);
        if (fd < 0)
                return -errno;

        return 0;
}

static void check_restrictions(BPFSandboxFeatures features, const char *dir, const char *sgid_file, int policy_map_id) {
        _cleanup_free_ char *p = NULL, *fifo = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        /* Plain fork()/clone3() keep working, and the children are restricted too. */
        ASSERT_OK(try_clone3(0));
        ASSERT_ERROR(try_clone3(CLONE_NEWUTS), EPERM);
        ASSERT_ERROR(try_clone3(CLONE_NEWUSER), EPERM);
        ASSERT_ERROR(try_clone(CLONE_NEWNET), EPERM);

        r = ASSERT_OK(pidref_safe_fork("(grandchild)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                ASSERT_ERROR(try_clone3(CLONE_NEWUTS), EPERM);
                _exit(EXIT_SUCCESS);
        }

        if (FLAGS_SET(features, BPF_SANDBOX_NAMESPACES)) {
                ASSERT_ERROR_ERRNO(unshare(CLONE_NEWUTS), EPERM);
                ASSERT_ERROR_ERRNO(unshare(CLONE_NEWUSER), EPERM);

                /* Joining is refused as well, even our own namespace. */
                fd = ASSERT_OK_ERRNO(open("/proc/self/ns/uts", O_RDONLY|O_CLOEXEC));
                ASSERT_ERROR_ERRNO(setns(fd, CLONE_NEWUTS), EPERM);
                fd = safe_close(fd);
        } else
                log_notice("Kernel lacks the namespace hooks, not checking unshare() and setns().");

        if (FLAGS_SET(features, BPF_SANDBOX_SUID_SGID)) {
                ASSERT_OK(try_openat2(dir, "plain", 0755));
                ASSERT_ERROR(try_openat2(dir, "suid", 0755 | S_ISUID), EPERM);
                ASSERT_ERROR(try_openat2(dir, "sgid", 0755 | S_ISGID), EPERM);

                r = try_tmpfile(dir, 0644);
                if (r >= 0) {
                        ASSERT_ERROR(try_tmpfile(dir, 0644 | S_ISUID), EPERM);
                        ASSERT_ERROR(try_tmpfile(dir, 0644 | S_ISGID), EPERM);
                } else
                        log_notice_errno(r, "O_TMPFILE not supported, skipping its checks: %m");

                ASSERT_NOT_NULL(p = path_join(dir, "chmod"));
                fd = ASSERT_OK_ERRNO(open(p, O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC, 0644));
                ASSERT_OK_ERRNO(chmod(p, 0700));
                ASSERT_ERROR_ERRNO(chmod(p, 0755 | S_ISUID), EPERM);
                ASSERT_ERROR_ERRNO(fchmod(fd, 0755 | S_ISGID), EPERM);
                ASSERT_ERROR_ERRNO(fchmodat(AT_FDCWD, p, 0755 | S_ISUID | S_ISGID, 0), EPERM);
                fd = safe_close(fd);
                ASSERT_OK_ERRNO(unlink(p));

                ASSERT_NOT_NULL(fifo = path_join(dir, "fifo"));
                ASSERT_ERROR_ERRNO(mknod(fifo, S_IFIFO | 0644 | S_ISGID, 0), EPERM);
                ASSERT_OK_ERRNO(mknod(fifo, S_IFIFO | 0644, 0));
                ASSERT_OK_ERRNO(unlink(fifo));

                /* The kernel ignores these bits in mkdir(), hence there's nothing to refuse. */
                struct stat st;
                ASSERT_OK_ERRNO(mkdir(fifo, 0755 | S_ISUID | S_ISGID));
                ASSERT_OK_ERRNO(stat(fifo, &st));
                ASSERT_EQ(st.st_mode & (S_ISUID|S_ISGID), 0U);
                ASSERT_OK_ERRNO(rmdir(fifo));

                /* chown() strips the SUID bit, but keeps S_ISGID on files without group execute permission,
                 * by passing the remaining mode to the setattr hook. That must keep working, as nothing is
                 * added, and so must changing the mode while keeping the bits that are already set. */
                ASSERT_OK_ERRNO(chown(sgid_file, 1, 1));
                ASSERT_OK(write_string_file(sgid_file, "foo", WRITE_STRING_FILE_DISABLE_BUFFER));
                ASSERT_OK_ERRNO(chmod(sgid_file, 0640 | S_ISGID));
        } else
                log_notice("Kernel lacks hooks for RestrictSUIDSGID=, not checking it.");

        /* We may neither obtain the policy map to change our policy, nor any of the links to detach them. */
        ASSERT_ERROR_ERRNO(sym_bpf_map_get_fd_by_id(policy_map_id), EPERM);
}

TEST(bpf_sandbox) {
        _cleanup_(rm_rf_physical_and_freep) char *runtime_dir = NULL, *dir = NULL;
        _cleanup_(manager_freep) Manager *m = NULL, *m2 = NULL;
        _cleanup_(fdset_freep) FDSet *fds = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *sgid_file = NULL;
        _cleanup_close_ int fd = -EBADF;
        struct bpf_map_info info = {};
        uint32_t len = sizeof(info);
        BPFSandboxFeatures features;
        int r;

        if (getuid() != 0)
                return (void) log_tests_skipped("not running as root");

        ASSERT_NOT_NULL(runtime_dir = setup_fake_runtime_dir());

        r = manager_new(RUNTIME_SCOPE_SYSTEM, MANAGER_TEST_RUN_MINIMAL, &m);
        if (manager_errno_skip_test(r))
                return (void) log_tests_skipped_errno(r, "manager_new");
        ASSERT_OK(r);

        (void) bpf_sandbox_setup(m);
        features = m->bpf_sandbox_features;
        if (features == 0)
                return (void) log_tests_skipped("BPF LSM programs could not be loaded");

        ASSERT_OK(dlopen_bpf(LOG_DEBUG));
        ASSERT_OK_ERRNO(sym_bpf_obj_get_info_by_fd(m->bpf_sandbox_map_fd, &info, &len));

        /* Only restricted processes are refused. */
        fd = ASSERT_OK_ERRNO(sym_bpf_map_get_fd_by_id(info.id));
        fd = safe_close(fd);

        ASSERT_OK(mkdtemp_malloc("/tmp/test-bpf-sandbox-XXXXXX", &dir));
        ASSERT_NOT_NULL(sgid_file = path_join(dir, "chown-sgid"));
        fd = ASSERT_OK_ERRNO(open(sgid_file, O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC, 0644));
        ASSERT_OK_ERRNO(fchmod(fd, 0640 | S_ISUID | S_ISGID));
        fd = safe_close(fd);

        /* Unrestricted processes are not affected. */
        r = ASSERT_OK(pidref_safe_fork("(unrestricted)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                ASSERT_OK(try_clone3(CLONE_NEWUTS));
                ASSERT_OK(try_openat2(dir, "suid", 0755 | S_ISUID));
                _exit(EXIT_SUCCESS);
        }

        r = ASSERT_OK(pidref_safe_fork("(restricted)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                ASSERT_OK(bpf_sandbox_apply(m->bpf_sandbox_map_fd, NAMESPACE_FLAGS_ALL, /* restrict_suid_sgid= */ true));
                check_restrictions(features, dir, sgid_file, info.id);
                _exit(EXIT_SUCCESS);
        }

        /* A partial policy only restricts what it says. */
        r = ASSERT_OK(pidref_safe_fork("(partial)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                ASSERT_OK(bpf_sandbox_apply(m->bpf_sandbox_map_fd, CLONE_NEWUSER, /* restrict_suid_sgid= */ false));
                ASSERT_OK(try_clone3(CLONE_NEWUTS));
                ASSERT_ERROR(try_clone3(CLONE_NEWUSER), EPERM);
                ASSERT_OK(try_openat2(dir, "suid", 0755 | S_ISUID));

                /* Applying more restrictions adds to the existing ones. */
                ASSERT_OK(bpf_sandbox_apply(m->bpf_sandbox_map_fd, CLONE_NEWUTS, /* restrict_suid_sgid= */ false));
                ASSERT_ERROR(try_clone3(CLONE_NEWUTS), EPERM);
                ASSERT_ERROR(try_clone3(CLONE_NEWUSER), EPERM);
                _exit(EXIT_SUCCESS);
        }

        /* After reexec the new PID 1 keeps using the programs and the map. */
        ASSERT_NOT_NULL(fds = fdset_new());
        ASSERT_OK(open_serialization_file("test-bpf-sandbox", &f));
        ASSERT_OK(bpf_sandbox_serialize(m, f, fds));
        ASSERT_OK_ERRNO(fseeko(f, 0, SEEK_SET));

        ASSERT_OK(manager_new(RUNTIME_SCOPE_SYSTEM, MANAGER_TEST_RUN_MINIMAL, &m2));
        for (;;) {
                _cleanup_free_ char *line = NULL;

                r = ASSERT_OK(read_stripped_line(f, LONG_LINE_MAX, &line));
                if (r == 0)
                        break;

                bpf_sandbox_deserialize_item(m2, line, fds);
        }

        /* Detaching the original links and the map must not matter. */
        bpf_sandbox_done(m);

        ASSERT_OK(bpf_sandbox_setup(m2));
        ASSERT_EQ(m2->bpf_sandbox_features, features);

        r = ASSERT_OK(pidref_safe_fork("(restricted-reexec)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                ASSERT_OK(bpf_sandbox_apply(m2->bpf_sandbox_map_fd, NAMESPACE_FLAGS_ALL, /* restrict_suid_sgid= */ true));
                check_restrictions(m2->bpf_sandbox_features, dir, sgid_file, info.id);
                _exit(EXIT_SUCCESS);
        }
}

static int intro(void) {
        struct rlimit rl;

        ASSERT_OK(getrlimit(RLIMIT_MEMLOCK, &rl));
        rl.rlim_cur = rl.rlim_max = MAX(rl.rlim_max, CAN_MEMLOCK_SIZE);
        (void) setrlimit_closest(RLIMIT_MEMLOCK, &rl);

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
