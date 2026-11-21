/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <linux/sched.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "landlock-util.h"
#include "pidref.h"
#include "process-util.h"
#include "tests.h"

static int clone3_and_wait(uint64_t flags) {
        struct clone_args args = {
                .flags = flags,
                .exit_signal = SIGCHLD,
        };
        siginfo_t si = {};
        pid_t pid;

        pid = RET_NERRNO((pid_t) syscall(__NR_clone3, &args, sizeof(args)));
        if (pid < 0)
                return pid;
        if (pid == 0)
                _exit(EXIT_SUCCESS);

        ASSERT_OK_ERRNO(waitid(P_PID, pid, &si, WEXITED));
        ASSERT_EQ(si.si_code, CLD_EXITED);
        ASSERT_EQ(si.si_status, EXIT_SUCCESS);
        return 0;
}

static bool can_unshare_userns(void) {
        _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;
        int r;

        ASSERT_OK(r = pidref_safe_fork("(can-unshare-userns)", /* flags= */ 0, &pid));
        if (r == 0)
                _exit(unshare(CLONE_NEWUSER) < 0 ? EXIT_FAILURE : EXIT_SUCCESS);

        return ASSERT_OK(pidref_wait_for_terminate_and_check("(can-unshare-userns)", &pid, /* flags= */ 0)) == EXIT_SUCCESS;
}

static bool landlock_supports_permissions(void) {
        int abi;

        abi = landlock_abi_version();
        if (abi == -EOPNOTSUPP) {
                log_tests_skipped("Landlock not available");
                return false;
        }
        ASSERT_OK(abi);
        if (abi < MAX(LANDLOCK_ABI_NAMESPACE_USE, LANDLOCK_ABI_CAPABILITY_USE)) {
                log_tests_skipped("Landlock does not support namespace and capability restrictions");
                return false;
        }

        return true;
}

TEST(restrict_namespaces) {
        int r;

        if (!landlock_supports_permissions())
                return;

        if (!can_unshare_userns())
                return (void) log_tests_skipped("Cannot create user namespaces");

        r = ASSERT_OK(pidref_safe_fork("(landlock-restrict-ns)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                LandlockRuleset ruleset = {};

                /* Multiple restrictions of the same category are intersected: the effective set of
                 * allowed namespace types is user and uts. */
                ASSERT_OK(landlock_ruleset_restrict_namespaces(&ruleset, CLONE_NEWUSER|CLONE_NEWUTS|CLONE_NEWNET));
                ASSERT_OK(landlock_ruleset_restrict_namespaces(&ruleset, CLONE_NEWUSER|CLONE_NEWUTS|CLONE_NEWIPC));

                ASSERT_OK(proc_set_nnp());
                ASSERT_OK(landlock_ruleset_enforce(&ruleset));

                /* Acquire CAP_SYS_ADMIN in a new user namespace, so that the only thing that can deny the
                 * namespace operations below is the Landlock domain. */
                ASSERT_OK_ERRNO(unshare(CLONE_NEWUSER));

                ASSERT_OK_ERRNO(unshare(CLONE_NEWUTS));
                ASSERT_ERROR_ERRNO(unshare(CLONE_NEWNET), EPERM);
                ASSERT_ERROR_ERRNO(unshare(CLONE_NEWIPC), EPERM);
                ASSERT_ERROR_ERRNO(unshare(CLONE_NEWUTS|CLONE_NEWNET), EPERM);
                /* Creates a mount namespace without CLONE_NEWNS being passed. */
                ASSERT_ERROR_ERRNO(unshare(UNSHARE_EMPTY_MNTNS), EPERM);

                /* clone3() must not be blocked wholesale, only the restricted namespace types. */
                ASSERT_OK(clone3_and_wait(0));
                ASSERT_OK(clone3_and_wait(CLONE_NEWUTS));
                ASSERT_ERROR(clone3_and_wait(CLONE_NEWNET), EPERM);
                ASSERT_ERROR(clone3_and_wait(CLONE_NEWUTS|CLONE_NEWIPC), EPERM);

                _exit(EXIT_SUCCESS);
        }

        r = ASSERT_OK(pidref_safe_fork("(landlock-restrict-all-ns)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                LandlockRuleset ruleset = {};

                ASSERT_OK(landlock_ruleset_restrict_namespaces(&ruleset, 0));
                ASSERT_OK(proc_set_nnp());
                ASSERT_OK(landlock_ruleset_enforce(&ruleset));

                ASSERT_ERROR_ERRNO(unshare(CLONE_NEWUSER), EPERM);
                ASSERT_ERROR(clone3_and_wait(CLONE_NEWUSER), EPERM);

                _exit(EXIT_SUCCESS);
        }
}

TEST(restrict_namespaces_mount_api) {
        int r;

        if (!landlock_supports_permissions())
                return;

        if (!can_unshare_userns())
                return (void) log_tests_skipped("Cannot create user namespaces");

        r = ASSERT_OK(pidref_safe_fork("(landlock-restrict-mount-api)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                LandlockRuleset ruleset = {};
                unsigned flags;

                /* Acquire CAP_SYS_ADMIN over a mount namespace of our own, so that the only thing that can
                 * deny the mount API calls below is the Landlock domain. */
                ASSERT_OK_ERRNO(unshare(CLONE_NEWUSER|CLONE_NEWNS));

                _cleanup_close_ int fs_fd = ASSERT_OK_ERRNO(fsopen("tmpfs", FSOPEN_CLOEXEC));
                ASSERT_OK_ERRNO(fsconfig(fs_fd, FSCONFIG_CMD_CREATE, /* key= */ NULL, /* value= */ NULL, /* aux= */ 0));
                _cleanup_close_ int mnt_fd = ASSERT_OK_ERRNO(fsmount(fs_fd, FSMOUNT_CLOEXEC, /* attr_flags= */ 0));
                safe_close(ASSERT_OK_ERRNO(open_tree(mnt_fd, "", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH)));

                ASSERT_OK(landlock_ruleset_restrict_namespaces(&ruleset, CLONE_NEWUSER));
                ASSERT_OK(proc_set_nnp());
                ASSERT_OK(landlock_ruleset_enforce(&ruleset));

                /* Unlike the seccomp implementation, Landlock also denies anonymous mount namespaces. */
                ASSERT_ERROR_ERRNO(open_tree(mnt_fd, "", OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH), EPERM);
                ASSERT_ERROR_ERRNO(open_tree(mnt_fd, "", OPEN_TREE_NAMESPACE|OPEN_TREE_CLOEXEC|AT_EMPTY_PATH), EPERM);

                FOREACH_ARGUMENT(flags, FSMOUNT_CLOEXEC, FSMOUNT_CLOEXEC|FSMOUNT_NAMESPACE) {
                        safe_close(fs_fd);
                        fs_fd = ASSERT_OK_ERRNO(fsopen("tmpfs", FSOPEN_CLOEXEC));
                        ASSERT_OK_ERRNO(fsconfig(fs_fd, FSCONFIG_CMD_CREATE, /* key= */ NULL, /* value= */ NULL, /* aux= */ 0));
                        ASSERT_ERROR_ERRNO(fsmount(fs_fd, flags, /* attr_flags= */ 0), EPERM);
                }

                _exit(EXIT_SUCCESS);
        }
}

TEST(restrict_ptrace) {
        bool userns;
        int r;

        if (!landlock_supports_permissions())
                return;

        userns = can_unshare_userns();

        r = ASSERT_OK(pidref_safe_fork("(landlock-restrict-ptrace)", FORK_LOG|FORK_WAIT, /* ret= */ NULL));
        if (r == 0) {
                _cleanup_(pidref_done_sigkill_wait) PidRef child = PIDREF_NULL;
                _cleanup_free_ char *exe = NULL;
                LandlockRuleset ruleset = {};
                const char *parent_exe = procfs_file_alloca(getppid(), "exe");

                ASSERT_OK(readlink_malloc(parent_exe, &exe));
                exe = mfree(exe);

                ASSERT_OK(landlock_ruleset_restrict_ptrace(&ruleset));
                ASSERT_OK(proc_set_nnp());
                ASSERT_OK(landlock_ruleset_enforce(&ruleset));

                /* Processes outside of the domain cannot be inspected anymore... */
                ASSERT_ERROR(readlink_malloc(parent_exe, &exe), EACCES);

                /* ... but processes we started ourselves can. */
                r = ASSERT_OK(pidref_safe_fork("(landlock-ptrace-child)", FORK_DEATHSIG_SIGKILL, &child));
                if (r == 0)
                        freeze();

                ASSERT_OK(readlink_malloc(procfs_file_alloca(child.pid, "exe"), &exe));

                /* Nothing else is restricted: neither namespaces nor capabilities. */
                if (userns) {
                        ASSERT_OK_ERRNO(unshare(CLONE_NEWUSER));
                        ASSERT_OK_ERRNO(unshare(CLONE_NEWNS|CLONE_NEWNET));
                        ASSERT_OK(clone3_and_wait(CLONE_NEWUTS));
                }

                _exit(EXIT_SUCCESS);
        }
}

DEFINE_TEST_MAIN(LOG_DEBUG);
