/*
 * ZEUS user-mode emulation: processes
 *
 * Each ZEUS process is a host process running this emulator.  fork is the
 * host's fork; exec replaces the host process with a fresh emulator for
 * the new program, so descriptors, the current directory, ignored signals
 * and the process id carry over exactly as the host carries them.
 *
 * ZEUS process ids are 16 bits and host ids are not, so a host id is
 * folded into the ZEUS range.  kill finds the host process for a ZEUS id
 * among the caller's relatives, and otherwise among the processes of the
 * caller's session that fold to that id.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/bswap.h"
#include "qemu.h"
#include <sys/wait.h>

#define ENV_PREFIX   "QEMU_ZEUS_"
#define ENV_EXACT    ENV_PREFIX "ENV=1"
#define ENV_CHILDREN ENV_PREFIX "CHILDREN="

static GHashTable *children;    /* ZEUS pid -> host pid */
static char *self_exe;
static char **self_opts;        /* emulator options to pass on at exec */

int zeus_pid(pid_t host)
{
    return host <= 0 ? host : (host % 30000) + 2;
}

static void child_add(pid_t host)
{
    if (!children) {
        children = g_hash_table_new(NULL, NULL);
    }
    g_hash_table_insert(children, GINT_TO_POINTER(zeus_pid(host)),
                        GINT_TO_POINTER(host));
}

/* Host pid for a ZEUS pid the process may signal, or -1. */
static pid_t host_pid(int zpid)
{
    gpointer h;

    if (zpid == zeus_pid(getpid())) {
        return getpid();
    }
    if (zpid == zeus_pid(getppid())) {
        return getppid();
    }
    if (children &&
        g_hash_table_lookup_extended(children, GINT_TO_POINTER(zpid),
                                     NULL, &h)) {
        return GPOINTER_TO_INT(h);
    }

    /*
     * Any other process (a sibling, say, as when a shell runs kill as a
     * command): every host pid that folds to this ZEUS pid, accepted only
     * if it is in our session and, where the host can tell us, runs this
     * emulator.
     */
    if (zpid >= 2) {
        pid_t sid = getsid(0);

        for (long host = zpid - 2; host < (1L << 22) + 30000; host += 30000) {
            g_autofree char *link = NULL;
            char exe[PATH_MAX];
            ssize_t n;

            if (host <= 1 || getsid(host) != sid) {
                continue;
            }
            link = g_strdup_printf("/proc/%ld/exe", host);
            n = readlink(link, exe, sizeof(exe) - 1);
            if (n > 0) {
                exe[n] = '\0';
                if (strcmp(exe, self_exe)) {
                    continue;
                }
            }
            return host;
        }
    }
    return -1;
}

/*
 * Called once at start: remember how to re-run the emulator, and pick up
 * what the previous program in this process left for us.
 */
void zeus_proc_init(const char *argv0, char **opts)
{
    const char *kids = getenv(ENV_PREFIX "CHILDREN");
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);

    if (n > 0) {
        buf[n] = '\0';
        self_exe = g_strdup(buf);
    } else {
        self_exe = g_find_program_in_path(argv0);
        if (!self_exe) {
            self_exe = g_strdup(argv0);
        }
    }
    self_opts = g_strdupv(opts);

    if (kids) {
        g_auto(GStrv) v = g_strsplit(kids, ",", -1);

        for (int i = 0; v[i]; i++) {
            if (v[i][0]) {
                child_add(atoi(v[i]));
            }
        }
    }
}

/* True when the environment was handed over by a ZEUS exec. */
bool zeus_env_is_exact(void)
{
    return getenv(ENV_PREFIX "ENV") != NULL;
}

bool zeus_env_is_internal(const char *entry)
{
    return g_str_has_prefix(entry, ENV_PREFIX);
}

/* ---- fork and wait ---- */

void zeus_fork(CPUZ8000State *env)
{
    pid_t parent = getpid();
    pid_t pid;

    fflush(NULL);
    fork_start();
    pid = fork();
    fork_end(pid);
    if (pid < 0) {
        env->regs[4] = 11;              /* EAGAIN */
        env->fcw |= F_C;
        return;
    }
    env->fcw &= ~F_C;
    if (pid == 0) {
        /* the child resumes right after the call, with the parent's pid */
        if (children) {
            g_hash_table_remove_all(children);
        }
        env->regs[4] = zeus_pid(parent);
    } else {
        /* the parent resumes one instruction later */
        child_add(pid);
        env->regs[4] = zeus_pid(pid);
        env->pc += 2;
    }
}

/* wait: pid in R4, status in R5; returns a host errno or 0 */
int zeus_wait(CPUZ8000State *env)
{
    int status, zstatus;
    pid_t pid = waitpid(-1, &status, 0);

    if (pid < 0) {
        return errno;
    }
    if (children) {
        g_hash_table_remove(children, GINT_TO_POINTER(zeus_pid(pid)));
    }
    if (WIFEXITED(status)) {
        zstatus = WEXITSTATUS(status) << 8;
    } else if (WIFSIGNALED(status)) {
        int zsig = host_to_target_signal(WTERMSIG(status));

        zstatus = zsig ? zsig : TARGET_SIGKILL;
#ifdef WCOREDUMP
        if (WCOREDUMP(status)) {
            zstatus |= 0x80;
        }
#endif
    } else {
        zstatus = 0;
    }
    env->regs[4] = zeus_pid(pid);
    env->regs[5] = zstatus;
    return 0;
}

int zeus_kill(int zpid, int zsig)
{
    int hsig = zsig ? target_to_host_signal(zsig) : 0;
    pid_t pid;

    if (zsig < 0 || zsig >= TARGET_NSIG || (zsig && !hsig)) {
        return EINVAL;
    }
    if (zpid == 0) {
        pid = 0;                        /* the caller's process group */
    } else {
        pid = host_pid(zpid);
        if (pid < 0) {
            return ESRCH;
        }
    }
    return kill(pid, hsig) < 0 ? errno : 0;
}

/* ---- exec ---- */

/* Copy a NULL-terminated vector of data-space string pointers. */
static char **read_vector(CPUZ8000State *env, uint32_t addr, size_t *bytes)
{
    g_autoptr(GPtrArray) v = g_ptr_array_new_with_free_func(g_free);

    bool segmented = get_task_state(env_cpu(env))->info->segmented;
    int psize = segmented ? 4 : 2;

    for (;;) {
        uint8_t *p = zeus_data_ptr(env, addr, psize, false);
        uint32_t s;
        char *str;

        if (!p) {
            return NULL;
        }
        s = segmented ? zeus_long_to_ptr(ldl_be_p(p)) : lduw_be_p(p);
        if (!s) {
            break;
        }
        str = zeus_data_string(env, s);
        if (!str) {
            return NULL;
        }
        *bytes += strlen(str) + 3;
        g_ptr_array_add(v, str);
        addr += psize;
    }
    g_ptr_array_add(v, NULL);
    return (char **)g_ptr_array_free(g_steal_pointer(&v), FALSE);
}

/*
 * exece(path, argv, envp).  Returns a host errno; does not return on
 * success.
 */
int zeus_exec(CPUZ8000State *env, uint32_t path_addr, uint32_t argv_addr,
              uint32_t envp_addr)
{
    g_autofree char *gpath = zeus_data_string(env, path_addr);
    g_autofree char *canon = NULL;
    g_autofree char *host = NULL;
    g_auto(GStrv) gargv = NULL;
    g_auto(GStrv) genvp = NULL;
    g_autoptr(GPtrArray) argv = g_ptr_array_new();
    g_autoptr(GPtrArray) envp = g_ptr_array_new();
    g_autoptr(GString) kids = g_string_new(ENV_CHILDREN);
    size_t bytes = 0;
    uint8_t hdr[2];
    int fd, r;

    if (!gpath) {
        return EFAULT;
    }
    gargv = read_vector(env, argv_addr, &bytes);
    genvp = envp_addr ? read_vector(env, envp_addr, &bytes)
                      : g_new0(char *, 1);
    if (!gargv || !genvp) {
        return EFAULT;
    }
    if (bytes > ZEUS_SPACE_SIZE / 2) {
        return E2BIG;
    }

    /* the file must be there, executable, and a program we can load */
    r = zeus_fs_access(gpath, 1);
    if (r < 0) {
        return -r;
    }
    host = zeus_resolve(gpath, &canon);
    fd = open(host, O_RDONLY);
    if (fd < 0) {
        return errno;
    }
    r = read(fd, hdr, 2);
    close(fd);
    if (r != 2 || (hdr[0] != 0xe7 && hdr[0] != 0xe6) ||
        (hdr[1] != 0x07 && hdr[1] != 0x11)) {
        return ENOEXEC;         /* a shell will try it as a script */
    }

    /* emulator options, then the program by its guest path */
    g_ptr_array_add(argv, self_exe);
    for (int i = 0; self_opts && self_opts[i]; i++) {
        g_ptr_array_add(argv, self_opts[i]);
    }
    if (gargv[0]) {
        g_ptr_array_add(argv, (char *)"-0");
        g_ptr_array_add(argv, gargv[0]);
    }
    g_ptr_array_add(argv, canon ? canon : host);
    for (int i = 1; gargv[0] && gargv[i]; i++) {
        g_ptr_array_add(argv, gargv[i]);
    }
    g_ptr_array_add(argv, NULL);

    /* the program's environment, exactly, plus what we need to carry */
    for (int i = 0; genvp[i]; i++) {
        if (!zeus_env_is_internal(genvp[i])) {
            g_ptr_array_add(envp, genvp[i]);
        }
    }
    g_ptr_array_add(envp, (char *)ENV_EXACT);
    if (children) {
        GHashTableIter it;
        gpointer k, h;

        g_hash_table_iter_init(&it, children);
        while (g_hash_table_iter_next(&it, &k, &h)) {
            g_string_append_printf(kids, "%d,", GPOINTER_TO_INT(h));
        }
    }
    g_ptr_array_add(envp, kids->str);
    g_ptr_array_add(envp, NULL);

    fflush(NULL);
    execve(self_exe, (char **)argv->pdata, (char **)envp->pdata);
    return errno;
}
