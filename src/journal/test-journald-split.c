/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "journald-context.h"
#include "journald-manager.h"
#include "tests.h"
#include "uid-classification.h"

static uid_t journal_uid(SplitMode mode, uid_t uid, uid_t owner_uid, uid_t userns_owner_uid) {
        ClientContext c = {
                .uid = uid,
                .owner_uid = owner_uid,
                .userns_owner_uid = userns_owner_uid,
        };

        return manager_journal_uid_for_context(mode, &c);
}

static bool in_system_journal(SplitMode mode, uid_t uid, uid_t owner_uid, uid_t userns_owner_uid) {
        return uid_for_system_journal(journal_uid(mode, uid, owner_uid, userns_owner_uid));
}

TEST(split_uid) {
        uid_t transient;

        ASSERT_EQ(manager_journal_uid_for_context(SPLIT_UID, NULL), 0u);

        /* Regular UIDs are split by UID, regardless of the owner */
        ASSERT_TRUE(in_system_journal(SPLIT_UID, 0, UID_INVALID, UID_INVALID));
        ASSERT_TRUE(in_system_journal(SPLIT_UID, 0, 1000, UID_INVALID));
        ASSERT_TRUE(in_system_journal(SPLIT_UID, UID_INVALID, 1000, UID_INVALID));
        ASSERT_EQ(journal_uid(SPLIT_UID, 1000, UID_INVALID, UID_INVALID), 1000u);
        ASSERT_EQ(journal_uid(SPLIT_UID, 1000, 1001, 1001), 1000u);

        FOREACH_ARGUMENT(transient, (uid_t) CONTAINER_UID_MIN + 0x10000, (uid_t) CONTAINER_UID_MIN + 0x10005, (uid_t) DYNAMIC_UID_MIN) {
                /* Transient UIDs are attributed to the user, if nsresourced allocated the user namespace for
                 * the user owning the cgroup, too */
                ASSERT_EQ(journal_uid(SPLIT_UID, transient, 1000, 1000), 1000u);

                /* … but not if the user namespace isn't registered for the same user (e.g. stale cgroup
                 * data, a DynamicUser= service or a container started by root in a user's slice) */
                ASSERT_TRUE(in_system_journal(SPLIT_UID, transient, 1000, UID_INVALID));
                ASSERT_TRUE(in_system_journal(SPLIT_UID, transient, 1000, 1001));
                ASSERT_TRUE(in_system_journal(SPLIT_UID, transient, 1000, 0));

                /* … or if the owner isn't a regular user */
                ASSERT_TRUE(in_system_journal(SPLIT_UID, transient, UID_INVALID, UID_INVALID));
                ASSERT_TRUE(in_system_journal(SPLIT_UID, transient, 0, 0));
                ASSERT_TRUE(in_system_journal(SPLIT_UID, transient, CONTAINER_UID_MIN + 0x20000, CONTAINER_UID_MIN + 0x20000));
        }
}

TEST(split_login) {
        ASSERT_EQ(manager_journal_uid_for_context(SPLIT_LOGIN, NULL), 0u);
        ASSERT_TRUE(in_system_journal(SPLIT_LOGIN, 0, 1000, UID_INVALID));
        ASSERT_TRUE(in_system_journal(SPLIT_LOGIN, 1000, UID_INVALID, UID_INVALID));
        ASSERT_EQ(journal_uid(SPLIT_LOGIN, 1001, 1000, UID_INVALID), 1000u);
        ASSERT_EQ(journal_uid(SPLIT_LOGIN, CONTAINER_UID_MIN + 0x10000, 1000, UID_INVALID), 1000u);
}

TEST(split_none) {
        ASSERT_TRUE(in_system_journal(SPLIT_NONE, 1000, 1000, UID_INVALID));
        ASSERT_TRUE(in_system_journal(SPLIT_NONE, CONTAINER_UID_MIN + 0x10000, 1000, 1000));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
