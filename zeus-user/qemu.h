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
#include "user/page-protection.h"
#include "target_cpu.h"

/* Size of one instruction or data space of a non-segmented program. */
#define ZEUS_SPACE_SIZE  0x10000

/* What the loader found; the first four fields are read by the gdb stub. */
struct image_info {
    abi_ulong code_offset;
    abi_ulong data_offset;
    abi_ulong saved_auxv;
    abi_ulong auxv_len;

    uint32_t entry;
    uint32_t brk;           /* first address after bss, in data space */
    bool split_id;          /* separate instruction and data spaces */
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
void *zeus_data_ptr(CPUZ8000State *env, uint32_t addr, uint32_t len,
                    bool write);
char *zeus_data_string(CPUZ8000State *env, uint32_t addr);

/* sout.c */
int zeus_load(const char *filename, char **argv, char **envp,
              CPUZ8000State *env, struct image_info *info);

/* signal.c */
void zeus_signal_init(void);

/* syscall.c */
void zeus_syscall(CPUZ8000State *env, int num);
char *zeus_host_path(const char *guest_path);

#endif
