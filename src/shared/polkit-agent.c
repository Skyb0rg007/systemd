/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <locale.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-util.h"
#include "escape.h"
#include "exec-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "log.h"
#include "memory-util.h"
#include "path-util.h"
#include "pidref.h"
#include "polkit-agent.h"
#include "process-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "user-util.h"

#if ENABLE_POLKIT
static PidRef agent_pidref = PIDREF_NULL;

/* Object path polkit expects an authentication agent to be registered under. */
#define POLKIT_AGENT_OBJECT_PATH "/org/freedesktop/PolicyKit1/AuthenticationAgent"

/* Socket-activated helper, available since polkit 124; older polkit needs the setuid binary instead. */
#define POLKIT_AGENT_HELPER_SOCKET "/run/polkit/agent-helper.socket"

/* Fallback setuid helper locations, by distro. */
static const char* const polkit_agent_helper_paths[] = {
        "/usr/lib/polkit-1/polkit-agent-helper-1",
        "/usr/libexec/polkit-1/polkit-agent-helper-1",
        "/usr/libexec/polkit-agent-helper-1",
        "/usr/lib/policykit-1/polkit-agent-helper-1",
        "/run/wrappers/bin/polkit-agent-helper-1", /* NixOS */
};

/* = PAM_MAX_RESP_SIZE (<security/_pam_types.h>), mirrored to avoid a PAM header dependency; the helper
 * splits longer responses across multiple lines. */
#define POLKIT_AGENT_MAX_RESPONSE_SIZE 512U

typedef struct AgentContext {
        int password_fd;
} AgentContext;

static int polkit_agent_open_tty(void) {
        _cleanup_close_pair_ int pipe_fd[2] = EBADF_PAIR;
        char notify_fd[DECIMAL_STR_MAX(int) + 1];
        int r;

        r = shall_fork_agent();
        if (r <= 0)
                return r;

        _cleanup_free_ char *pkttyagent = NULL;
        r = find_executable("pkttyagent", &pkttyagent);
        if (r == -ENOENT) {
                log_debug("pkttyagent binary not available, ignoring.");
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to determine whether pkttyagent binary exists: %m");

        if (pipe2(pipe_fd, 0) < 0)
                return -errno;

        xsprintf(notify_fd, "%i", pipe_fd[1]);

        r = fork_agent("(polkit-agent)",
                       &pipe_fd[1],
                       1,
                       &agent_pidref,
                       pkttyagent,
                       "--notify-fd", notify_fd,
                       "--fallback");
        if (r < 0)
                return log_error_errno(r, "Failed to fork polkit agent: %m");

        /* Close the writing side, because that's the one for the agent */
        pipe_fd[1] = safe_close(pipe_fd[1]);

        /* Wait until the agent closes the fd */
        (void) fd_wait_for_event(pipe_fd[0], POLLHUP, USEC_INFINITY);

        return 1;
}

static int read_password_response(int fd, char **ret) {
        _cleanup_(erase_and_freep) char *buf = NULL;
        size_t n = 0;
        int r;

        assert(fd >= 0);
        assert(ret);

        /* Byte-by-byte so we never read past the newline: whatever follows must stay available to the
         * invoked command. */

        buf = new(char, POLKIT_AGENT_MAX_RESPONSE_SIZE);
        if (!buf)
                return -ENOMEM;

        for (;;) {
                char c;
                ssize_t l;

                l = read(fd, &c, 1);
                if (l < 0) {
                        if (errno == EINTR)
                                continue;
                        if (errno == EAGAIN) {
                                r = fd_wait_for_event(fd, POLLIN, USEC_INFINITY);
                                if (r < 0)
                                        return r;
                                continue;
                        }

                        return -errno;
                }
                if (l == 0) {
                        if (n == 0)
                                return -ENODATA; /* EOF without any data */

                        break; /* Accept an unterminated final line */
                }

                if (c == '\n')
                        break;
                if (c == 0)
                        return -EINVAL;

                /* Leave room for the newline and the NUL byte the helper needs */
                if (n >= POLKIT_AGENT_MAX_RESPONSE_SIZE - 2)
                        return -ENOBUFS;

                buf[n++] = c;
        }

        buf[n] = 0;
        *ret = TAKE_PTR(buf);
        return 0;
}

static int helper_socket_connect(const char *user, int *ret) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(user);
        assert(ret);

        fd = socket(AF_UNIX, SOCK_STREAM|SOCK_CLOEXEC, 0);
        if (fd < 0)
                return -errno;

        r = connect_unix_path(fd, AT_FDCWD, POLKIT_AGENT_HELPER_SOCKET);
        if (r < 0)
                return r;

        /* The socket helper wants the username as the first line, before the cookie; the setuid helper
         * takes it as an argument instead. */
        _cleanup_free_ char *l = strjoin(user, "\n");
        if (!l)
                return -ENOMEM;

        r = loop_write(fd, l, SIZE_MAX);
        if (r < 0)
                return r;

        *ret = TAKE_FD(fd);
        return 0;
}

static int helper_spawn(const char *user, int *ret_input_fd, int *ret_output_fd, PidRef *ret_pidref) {
        _cleanup_close_pair_ int to_helper[2] = EBADF_PAIR, from_helper[2] = EBADF_PAIR;
        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        const char *path = NULL;
        int r;

        assert(user);
        assert(ret_input_fd);
        assert(ret_output_fd);
        assert(ret_pidref);

        FOREACH_ELEMENT(p, polkit_agent_helper_paths)
                if (access(*p, X_OK) >= 0) {
                        path = *p;
                        break;
                }
        if (!path)
                return -ENOENT;

        if (pipe2(to_helper, O_CLOEXEC) < 0)
                return -errno;
        if (pipe2(from_helper, O_CLOEXEC) < 0)
                return -errno;

        r = pidref_safe_fork_full(
                        "(polkit-agent-helper)",
                        (int[]) { to_helper[0], from_helper[1], STDERR_FILENO },
                        /* except_fds= */ NULL, /* n_except_fds= */ 0,
                        FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_REARRANGE_STDIO|FORK_LOG|FORK_RLIMIT_NOFILE_SAFE,
                        &pidref);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */
                execl(path, "polkit-agent-helper-1", user, NULL);
                log_error_errno(errno, "Failed to execute %s: %m", path);
                _exit(EXIT_FAILURE);
        }

        *ret_input_fd = TAKE_FD(from_helper[0]);
        *ret_output_fd = TAKE_FD(to_helper[1]);
        *ret_pidref = TAKE_PIDREF(pidref);
        return 0;
}

static int helper_converse(FILE *input, int output_fd, const char *cookie, int password_fd) {
        int r;

        assert(input);
        assert(output_fd >= 0);
        assert(cookie);
        assert(password_fd >= 0);

        /* Drives polkit-agent-helper-1's line protocol: send the cookie, answer PAM prompts until
         * SUCCESS/FAILURE. By SUCCESS the helper has already told polkitd via AuthenticationAgentResponse2(). */

        _cleanup_free_ char *l = strjoin(cookie, "\n");
        if (!l)
                return log_oom();

        r = loop_write(output_fd, l, SIZE_MAX);
        if (r < 0)
                return log_error_errno(r, "Failed to send cookie to polkit agent helper: %m");

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *e;

                /* READ_LINE_IS_A_TTY avoids peeking past the newline for CRLF: the helper blocks for our
                 * reply after each prompt, so peeking ahead would deadlock. */
                r = read_line_full(input, LONG_LINE_MAX, READ_LINE_IS_A_TTY, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read from polkit agent helper: %m");
                if (r == 0)
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "polkit agent helper terminated conversation prematurely.");

                if (streq(line, "SUCCESS"))
                        return 0;
                if (streq(line, "FAILURE"))
                        return log_error_errno(SYNTHETIC_ERRNO(EACCES), "polkit authentication failed.");

                e = startswith(line, "PAM_PROMPT_ECHO_OFF ") ?: startswith(line, "PAM_PROMPT_ECHO_ON ");
                if (e) {
                        _cleanup_free_ char *prompt = NULL;
                        _cleanup_(erase_and_freep) char *response = NULL, *response_line = NULL;

                        /* Escaped by the helper via g_strescape(), which our C unescaping can also parse. */
                        r = cunescape(e, UNESCAPE_RELAX, &prompt);
                        if (r < 0)
                                return log_error_errno(r, "Failed to unescape PAM prompt: %m");

                        /* Show the prompt on stderr, like sudo does. */
                        fputs(prompt, stderr);
                        fflush(stderr);

                        r = read_password_response(password_fd, &response);
                        fputc('\n', stderr);
                        if (r == -ENODATA)
                                return log_error_errno(r, "No response available for PAM prompt, refusing.");
                        if (r == -ENOBUFS)
                                return log_error_errno(r, "PAM response too long, refusing.");
                        if (r < 0)
                                return log_error_errno(r, "Failed to read PAM response: %m");

                        response_line = strjoin(response, "\n");
                        if (!response_line)
                                return log_oom();

                        r = loop_write(output_fd, response_line, SIZE_MAX);
                        if (r < 0)
                                return log_error_errno(r, "Failed to send PAM response to polkit agent helper: %m");

                        continue;
                }

                e = startswith(line, "PAM_TEXT_INFO ") ?: startswith(line, "PAM_ERROR_MSG ");
                if (e) {
                        _cleanup_free_ char *msg = NULL;

                        r = cunescape(e, UNESCAPE_RELAX, &msg);
                        if (r < 0)
                                return log_error_errno(r, "Failed to unescape PAM message: %m");

                        log_full(startswith(line, "PAM_ERROR_MSG ") ? LOG_ERR : LOG_INFO, "%s", msg);
                        continue;
                }

                log_debug("Ignoring unexpected line from polkit agent helper: %s", line);
        }
}

static int agent_authenticate(AgentContext *c, const char *user, const char *cookie) {
        _cleanup_(pidref_done) PidRef helper_pidref = PIDREF_NULL;
        _cleanup_close_ int socket_fd = -EBADF, input_fd = -EBADF, output_fd = -EBADF;
        _cleanup_fclose_ FILE *input = NULL;
        int r, write_fd;

        assert(c);
        assert(user);
        assert(cookie);

        r = helper_socket_connect(user, &socket_fd);
        if (r < 0)
                log_debug_errno(r, "Failed to connect to %s, falling back to setuid helper: %m", POLKIT_AGENT_HELPER_SOCKET);

        if (socket_fd >= 0) {
                input = take_fdopen(&socket_fd, "r");
                if (!input)
                        return log_oom();

                write_fd = fileno(input);
        } else {
                r = helper_spawn(user, &input_fd, &output_fd, &helper_pidref);
                if (r < 0)
                        return log_error_errno(r, "Failed to spawn polkit-agent-helper-1: %m");

                input = take_fdopen(&input_fd, "r");
                if (!input)
                        return log_oom();

                write_fd = output_fd;
        }

        r = helper_converse(input, write_fd, cookie, c->password_fd);

        /* Close our end first, so the helper notices we're done, before reaping it. */
        input = safe_fclose(input);
        output_fd = safe_close(output_fd);

        if (pidref_is_set(&helper_pidref))
                (void) pidref_wait_for_terminate_and_check("polkit-agent-helper-1", &helper_pidref, 0);

        return r;
}

static int verify_sender_is_polkit(sd_bus_message *m, sd_bus_error *error) {
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        const char *sender, *owner;
        int r;

        assert(m);

        /* polkitd drops root after startup, so require it to own the well-known bus name instead. */

        sender = sd_bus_message_get_sender(m);
        if (!sender)
                return sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED, "Sender of authentication request unknown.");

        r = sd_bus_get_name_creds(sd_bus_message_get_bus(m), "org.freedesktop.PolicyKit1", SD_BUS_CREDS_UNIQUE_NAME, &creds);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to determine owner of polkit bus name: %m");

        r = sd_bus_creds_get_unique_name(creds, &owner);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Failed to determine unique name of polkit bus name owner: %m");

        if (!streq(sender, owner))
                return sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED, "Authentication request not from polkit, refusing.");

        return 0;
}

static int method_begin_authentication(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        AgentContext *c = ASSERT_PTR(userdata);
        const char *action_id, *message, *icon_name, *cookie;
        uid_t selected = UID_INVALID;
        int r;

        assert(m);

        r = verify_sender_is_polkit(m, error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(m, "sss", &action_id, &message, &icon_name);
        if (r < 0)
                return r;

        r = sd_bus_message_skip(m, "a{ss}"); /* details */
        if (r < 0)
                return r;

        r = sd_bus_message_read(m, "s", &cookie);
        if (r < 0)
                return r;

        /* Prefer our own uid among the offered identities, like sudo, so the password is the caller's own;
         * else take the first one. */
        r = sd_bus_message_enter_container(m, 'a', "(sa{sv})");
        if (r < 0)
                return r;

        for (;;) {
                const char *kind;
                uid_t uid = UID_INVALID;

                r = sd_bus_message_enter_container(m, 'r', "sa{sv}");
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = sd_bus_message_read(m, "s", &kind);
                if (r < 0)
                        return r;

                r = sd_bus_message_enter_container(m, 'a', "{sv}");
                if (r < 0)
                        return r;

                for (;;) {
                        const char *key;

                        r = sd_bus_message_enter_container(m, 'e', "sv");
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        r = sd_bus_message_read(m, "s", &key);
                        if (r < 0)
                                return r;

                        if (streq(kind, "unix-user") && streq(key, "uid")) {
                                uint32_t u;

                                r = sd_bus_message_read(m, "v", "u", &u);
                                if (r < 0)
                                        return r;

                                uid = u;
                        } else {
                                r = sd_bus_message_skip(m, "v");
                                if (r < 0)
                                        return r;
                        }

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return r;
                }

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return r;

                if (uid_is_valid(uid) && (uid == getuid() || !uid_is_valid(selected)))
                        selected = uid;
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        if (!uid_is_valid(selected))
                return sd_bus_error_set(error, SD_BUS_ERROR_FAILED, "No UNIX user identity offered for authentication.");

        _cleanup_free_ char *user = uid_to_name(selected);
        if (!user)
                return -ENOMEM;

        log_debug("Authenticating as user '%s' for action '%s': %s", user, action_id, message);

        r = agent_authenticate(c, user, cookie);
        if (r < 0)
                return sd_bus_error_set_errnof(error, r, "Authentication as user '%s' failed: %m", user);

        return sd_bus_reply_method_return(m, NULL);
}

static int method_cancel_authentication(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        const char *cookie;
        int r;

        assert(m);

        r = verify_sender_is_polkit(m, error);
        if (r < 0)
                return r;

        r = sd_bus_message_read(m, "s", &cookie);
        if (r < 0)
                return r;

        /* Nothing to do here: authentication is handled synchronously in BeginAuthentication(), hence we
         * cannot be here while one is in progress. */
        log_debug("Received request to cancel authentication.");

        return sd_bus_reply_method_return(m, NULL);
}

static const sd_bus_vtable agent_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_METHOD_WITH_ARGS("BeginAuthentication",
                                SD_BUS_ARGS("s", action_id,
                                            "s", message,
                                            "s", icon_name,
                                            "a{ss}", details,
                                            "s", cookie,
                                            "a(sa{sv})", identities),
                                SD_BUS_NO_RESULT,
                                method_begin_authentication,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("CancelAuthentication",
                                SD_BUS_ARGS("s", cookie),
                                SD_BUS_NO_RESULT,
                                method_cancel_authentication,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END,
};

static int agent_register(sd_bus *bus, const PidRef *subject) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);
        assert(pidref_is_set(subject));

        r = sd_bus_message_new_method_call(
                        bus,
                        &m,
                        "org.freedesktop.PolicyKit1",
                        "/org/freedesktop/PolicyKit1/Authority",
                        "org.freedesktop.PolicyKit1.Authority",
                        "RegisterAuthenticationAgent");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'r', "sa{sv}");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "s", "unix-process");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'a', "{sv}");
        if (r < 0)
                return bus_log_create_error(r);

        /* Zero start-time makes polkit read it from /proc/ itself; newer polkit ignores pid/start-time in
         * favor of the pidfd anyway. */
        r = sd_bus_message_append(m, "{sv}", "pid", "u", (uint32_t) subject->pid);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "{sv}", "start-time", "t", UINT64_C(0));
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "{sv}", "uid", "i", (int32_t) getuid());
        if (r < 0)
                return bus_log_create_error(r);

        if (subject->fd >= 0) {
                r = sd_bus_message_append(m, "{sv}", "pidfd", "h", subject->fd);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        /* Localize polkit's messages to match ours; safe since we're in a forked child. */
        (void) setlocale(LC_ALL, "");
        const char *locale = setlocale(LC_MESSAGES, NULL);
        if (isempty(locale))
                locale = "C";

        r = sd_bus_message_append(m, "ss", locale, POLKIT_AGENT_OBJECT_PATH);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to register polkit authentication agent: %s", bus_error_message(&error, r));

        log_debug("Registered polkit authentication agent for " PID_FMT ".", subject->pid);
        return 0;
}

static int agent_child(int password_fd, int notify_fd, const PidRef *subject) {
        _cleanup_(sd_event_unrefp) sd_event *event = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        AgentContext c = { .password_fd = password_fd };
        int r;

        assert(password_fd >= 0);
        assert(notify_fd >= 0);

        r = sd_event_new(&event);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m");

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = sd_bus_add_object_vtable(bus, NULL, POLKIT_AGENT_OBJECT_PATH, "org.freedesktop.PolicyKit1.AuthenticationAgent", agent_vtable, &c);
        if (r < 0)
                return log_error_errno(r, "Failed to add authentication agent object: %m");

        r = sd_bus_attach_event(bus, event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        r = agent_register(bus, subject);
        if (r < 0)
                return r;

        /* Tell the parent we are ready to handle authentication requests */
        (void) safe_close(notify_fd);

        r = sd_event_loop(event);
        if (r < 0)
                return log_error_errno(r, "Failed to run event loop: %m");

        return 0;
}

static int polkit_agent_open_password_fd(int password_fd) {
        _cleanup_close_pair_ int pipe_fd[2] = EBADF_PAIR;
        _cleanup_(pidref_done) PidRef self = PIDREF_NULL;
        int except[3], n_except = 0, r;

        assert(password_fd >= 0);

        /* Answers PAM prompts with lines from password_fd instead of the TTY. Registered for our own pid,
         * so it only fires for requests we trigger. */

        r = pidref_set_self(&self);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire pidfd of ourselves: %m");

        if (pipe2(pipe_fd, O_CLOEXEC) < 0)
                return log_error_errno(errno, "Failed to allocate notification pipe: %m");

        except[n_except++] = password_fd;
        except[n_except++] = pipe_fd[1];
        if (self.fd >= 0)
                except[n_except++] = self.fd;

        r = pidref_safe_fork_full(
                        "(polkit-agent)",
                        /* stdio_fds= */ NULL,
                        except, n_except,
                        FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_CLOSE_ALL_FDS|FORK_REOPEN_LOG,
                        &agent_pidref);
        if (r < 0)
                return log_error_errno(r, "Failed to fork polkit agent: %m");
        if (r == 0) {
                /* Child */
                pipe_fd[0] = -EBADF; /* Closed by FORK_CLOSE_ALL_FDS */

                r = agent_child(password_fd, TAKE_FD(pipe_fd[1]), &self);
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        /* Close the writing side, because that's the one for the agent */
        pipe_fd[1] = safe_close(pipe_fd[1]);

        /* Wait until the agent registered itself (or died trying) */
        (void) fd_wait_for_event(pipe_fd[0], POLLHUP, USEC_INFINITY);

        return 1;
}

int polkit_agent_open_full(int password_fd) {

        if (pidref_is_set(&agent_pidref))
                return 0;

        /* Clients that run as root don't need to activate/query polkit */
        if (geteuid() == 0)
                return 0;

        if (password_fd >= 0)
                return polkit_agent_open_password_fd(password_fd);

        return polkit_agent_open_tty();
}

int polkit_agent_open(void) {
        return polkit_agent_open_full(/* password_fd= */ -EBADF);
}

void polkit_agent_close(void) {
        /* Inform agent that we are done */
        pidref_done_sigterm_wait(&agent_pidref);
}

#else

int polkit_agent_open_full(int password_fd) {
        return 0;
}

int polkit_agent_open(void) {
        return 0;
}

void polkit_agent_close(void) {
}

#endif

int polkit_agent_open_if_enabled_full(BusTransport transport, bool ask_password, int password_fd) {

        /* Open the polkit agent as a child process if necessary */

        if (transport != BUS_TRANSPORT_LOCAL)
                return 0;

        if (!ask_password)
                return 0;

        return polkit_agent_open_full(password_fd);
}

int polkit_agent_open_if_enabled(BusTransport transport, bool ask_password) {
        return polkit_agent_open_if_enabled_full(transport, ask_password, /* password_fd= */ -EBADF);
}
