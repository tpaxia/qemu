/*
 * ZEUS user-mode emulation
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef ZEUS_USER_QEMU_H
#define ZEUS_USER_QEMU_H

#include "cpu.h"
#include "qemu/units.h"
#include "user/abitypes.h"
#include "user/guest-host.h"
#include "exec/page-protection.h"
#include "user/page-protection.h"
#include "target_cpu.h"
#include "exec/gdbstub.h"
#include "gdbstub/user.h"
#include "gdbstub/syscalls.h"

/* Size of one segment, or of a space of a non-segmented program. */
#define ZEUS_SPACE_SIZE  0x10000

/* A segmented program can name 128 segments. */
#define ZEUS_MAX_SEGS    128

/*
 * A program pointer as the emulator carries it: the segment number in
 * bits 22-16 and the offset below.  A non-segmented program only has
 * offsets.  A segmented program keeps a pointer in two words, the first
 * with the segment number in its high byte.
 */
static inline uint32_t zeus_long_to_ptr(uint32_t l)
{
    return ((l >> 8) & 0x7f0000) | (l & 0xffff);
}

static inline uint32_t zeus_ptr_to_long(uint32_t p)
{
    return ((p & 0x7f0000) << 8) | (p & 0xffff);
}

/* One entry of a segmented process's segment table. */
struct zeus_seg {
    uint8_t no;
    bool code;              /* in the instruction space of a split image */
    uint32_t code_size;     /* instruction bytes at the start */
    uint32_t size;          /* bytes in use, in units of 256 */
};

/* What the loader found; the first four fields are read by the gdb stub. */
struct image_info {
    abi_ulong code_offset;
    abi_ulong data_offset;
    abi_ulong saved_auxv;
    abi_ulong auxv_len;

    uint32_t entry;
    uint32_t brk;           /* first address after bss, in data space */
    uint32_t text_size;     /* instruction space in use; 0 if not split */
    bool split_id;          /* separate instruction and data spaces */
    bool segmented;
    uint8_t stack_seg;      /* stack segment of a segmented program */
    int nsegs;
    struct zeus_seg segs[ZEUS_MAX_SEGS];
};

struct zeus_binprm {
    const char *filename;
};

typedef struct TaskState {
    pid_t ts_tid;
    struct image_info *info;
    struct zeus_binprm *bprm;
    int signal_pending;
    uint32_t brk;           /* current program break */
    uint32_t fault_addr;    /* guest address of the last memory fault */
    bool in_fpe;            /* the floating-point emulator is running */
} TaskState;

static inline TaskState *get_task_state(CPUState *cs)
{
    return cs->opaque;
}

extern __thread CPUState *thread_cpu;

void fork_start(void);
void fork_end(pid_t pid);

/*
 * ZEUS signal numbers (sys/signal.h).  The names follow the modern
 * spelling used by generic code; signals ZEUS does not have are -1.
 */
#define TARGET_NSIG      20
#define TARGET_SIGHUP    1
#define TARGET_SIGINT    2
#define TARGET_SIGQUIT   3
#define TARGET_SIGILL    4
#define TARGET_SIGTRAP   5
#define TARGET_SIGABRT   6      /* SIGIOT */
#define TARGET_SIGEMT    7
#define TARGET_SIGFPE    8
#define TARGET_SIGKILL   9
#define TARGET_SIGBUS    10
#define TARGET_SIGSEGV   11
#define TARGET_SIGSYS    12
#define TARGET_SIGPIPE   13
#define TARGET_SIGALRM   14
#define TARGET_SIGTERM   15
#define TARGET_SIGUSR1   16
#define TARGET_SIGUSR2   17
#define TARGET_SIGCHLD   18     /* SIGCLD */
#define TARGET_SIGPWR    19
#define TARGET_SIGURG    (-1)
#define TARGET_SIGSTOP   (-1)
#define TARGET_SIGTSTP   (-1)
#define TARGET_SIGCONT   (-1)
#define TARGET_SIGTTIN   (-1)
#define TARGET_SIGTTOU   (-1)
#define TARGET_SIGIO     (-1)
#define TARGET_SIGXCPU   (-1)
#define TARGET_SIGXFSZ   (-1)
#define TARGET_SIGVTALRM (-1)
#define TARGET_SIGPROF   (-1)
#define TARGET_SIGWINCH  (-1)
extern int do_strace;
extern const char *zeus_sysroot;

/* memory.c */
void zeus_memory_init(void);
void zeus_map_space(uint32_t base);
uint32_t zeus_stack_ptr(CPUZ8000State *env);
void *zeus_data_ptr(CPUZ8000State *env, uint32_t addr, uint32_t len,
                    bool write);
char *zeus_data_string(CPUZ8000State *env, uint32_t addr);

/* sout.c */
int zeus_load(const char *filename, char **argv, char **envp,
              CPUZ8000State *env, struct image_info *info);
int zeus_overlay(const char *filename, CPUZ8000State *env,
                 struct image_info *info);

/* fpe.c */
bool zeus_fpe_enter(CPUZ8000State *env);
void zeus_fpe_call(CPUZ8000State *env, int num);

/* signal.c */
void zeus_signal_init(void);
int host_to_target_signal(int sig);
int target_to_host_signal(int sig);
uint32_t zeus_sig(int zsig, uint32_t handler, bool *ok);
void zeus_process_signals(CPUZ8000State *env);
void zeus_sigreturn(CPUZ8000State *env);
void zeus_force_signal(CPUZ8000State *env, int zsig, const char *what);
G_NORETURN void zeus_die(int zsig);

/* proc.c: calls return 0 or a host errno */
void zeus_proc_init(const char *argv0, char **opts);
bool zeus_env_is_exact(void);
bool zeus_env_is_internal(const char *entry);
int zeus_pid(pid_t host);
void zeus_fork(CPUZ8000State *env);
int zeus_wait(CPUZ8000State *env);
int zeus_kill(int zpid, int zsig);
int zeus_exec(CPUZ8000State *env, uint32_t path_addr, uint32_t argv_addr,
              uint32_t envp_addr);

/* tty.c: returns 0 or a ZEUS error number */
int zeus_ioctl(CPUZ8000State *env, int fd, uint32_t req, uint32_t arg);

/* syscall.c */
void zeus_syscall(CPUZ8000State *env, int num);

/*
 * The identity the program runs under.  Host user and group ids mean
 * nothing to ZEUS, so the program is the ZEUS super-user.
 */
#define ZEUS_UID 0
#define ZEUS_GID 0

/* fs.c: all return 0 or a descriptor, or a negative host errno */
void zeus_fs_init(void);
char *zeus_resolve(const char *gpath, char **canon);
char *zeus_host_path(const char *guest_path);
int zeus_fs_open(const char *gpath, int flags, int mode);
void zeus_fs_close(int fd);
void zeus_fs_dup(int oldfd, int newfd);
int zeus_fs_stat(const char *gpath, uint8_t *buf);
int zeus_fs_fstat(int fd, uint8_t *buf);
int zeus_fs_chdir(const char *gpath);
int zeus_fs_unlink(const char *gpath);
int zeus_fs_link(const char *gold, const char *gnew);
int zeus_fs_chmod(const char *gpath, int mode);
int zeus_fs_chown(const char *gpath, int uid, int gid);
int zeus_fs_access(const char *gpath, int amode);

#endif
