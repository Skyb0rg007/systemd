/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/sched.h>
#include <sched.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "errno-util.h"
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

TEST(restrict_namespaces) {
        int abi, r;

        abi = landlock_abi_version();
        if (abi == -EOPNOTSUPP)
                return (void) log_tests_skipped("Landlock not available");
        ASSERT_OK(abi);
        if (abi < LANDLOCK_ABI_NAMESPACE_USE)
                return (void) log_tests_skipped("Landlock does not support namespace restrictions");

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

DEFINE_TEST_MAIN(LOG_DEBUG);
