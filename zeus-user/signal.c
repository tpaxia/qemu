/*
 * ZEUS user-mode emulation: host signals
 *
 * Memory faults: a write to a page holding translated code is resolved by
 * the translator; any other fault taken on behalf of the guest ends the CPU
 * loop iteration with a segment trap.
 *
 * ZEUS signals: a signal the program catches is noted by a host handler and
 * delivered from the CPU loop, the way the ZEUS kernel delivers it: a
 * six-byte frame (PC segment word, PC offset, FCW) is pushed on the
 * program's stack and the PC is set to the handler.  System call 0 pops the
 * frame.  As in ZEUS, a caught signal reverts to its default action when it
 * is delivered, except SIGILL and SIGTRAP.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu.h"
#include "accel/tcg/cpu-ops.h"
#include "user/cpu_loop.h"
#include "user/signal.h"
#include "tcg/tcg.h"
#include "host-signal.h"

/* Host signal used to interrupt a running CPU (set in zeus_signal_init). */
int host_interrupt_signal;

/* ZEUS signal number -> host signal number, 0 where there is no match. */
static const int zeus_to_host[TARGET_NSIG] = {
    [TARGET_SIGHUP] = SIGHUP,   [TARGET_SIGINT] = SIGINT,
    [TARGET_SIGQUIT] = SIGQUIT, [TARGET_SIGILL] = SIGILL,
    [TARGET_SIGTRAP] = SIGTRAP, [TARGET_SIGABRT] = SIGABRT,
    [TARGET_SIGFPE] = SIGFPE,   [TARGET_SIGKILL] = SIGKILL,
    [TARGET_SIGBUS] = SIGBUS,   [TARGET_SIGSEGV] = SIGSEGV,
    [TARGET_SIGSYS] = SIGSYS,   [TARGET_SIGPIPE] = SIGPIPE,
    [TARGET_SIGALRM] = SIGALRM, [TARGET_SIGTERM] = SIGTERM,
    [TARGET_SIGUSR1] = SIGUSR1, [TARGET_SIGUSR2] = SIGUSR2,
    [TARGET_SIGCHLD] = SIGCHLD,
};

int target_to_host_signal(int sig)
{
    if (sig < 1 || sig >= TARGET_NSIG) {
        return sig;
    }
    return zeus_to_host[sig];
}

int host_to_target_signal(int sig)
{
    for (int i = 1; i < TARGET_NSIG; i++) {
        if (zeus_to_host[i] == sig) {
            return i;
        }
    }
    return 0;
}

/* What the program asked for each signal: 0 default, 1 ignore, or handler */
static uint32_t handlers[TARGET_NSIG];
static volatile sig_atomic_t pending[TARGET_NSIG];

static void guest_signal_handler(int host_sig)
{
    int zsig = host_to_target_signal(host_sig);

    if (zsig > 0 && zsig < TARGET_NSIG) {
        pending[zsig] = 1;
        if (thread_cpu) {
            get_task_state(thread_cpu)->signal_pending = 1;
            cpu_exit(thread_cpu);
        }
    }
}

/* Die the way a ZEUS process dies of a signal, so that a parent sees it. */
void zeus_die(int zsig)
{
    int host = target_to_host_signal(zsig);
    struct sigaction act = { .sa_handler = SIG_DFL };
    sigset_t set;

    fflush(NULL);
    if (host > 0) {
        sigaction(host, &act, NULL);
        sigemptyset(&set);
        sigaddset(&set, host);
        sigprocmask(SIG_UNBLOCK, &set, NULL);
        raise(host);
    }
    _exit(128 + zsig);
}

/*
 * sig(signo, handler): returns the previous value.  *ok is false for a
 * signal that cannot be set.
 */
uint32_t zeus_sig(int zsig, uint32_t handler, bool *ok)
{
    int host = target_to_host_signal(zsig);
    struct sigaction act = { 0 };
    uint32_t old;

    *ok = zsig > 0 && zsig < TARGET_NSIG && zsig != TARGET_SIGKILL &&
          host > 0;
    if (!*ok) {
        return 0;
    }
    old = handlers[zsig];
    handlers[zsig] = handler;
    sigemptyset(&act.sa_mask);
    if (handler == 0) {
        act.sa_handler = SIG_DFL;
    } else if (handler == 1) {
        act.sa_handler = SIG_IGN;
    } else {
        /* no SA_RESTART: an interrupted call returns EINTR, as in ZEUS */
        act.sa_handler = guest_signal_handler;
    }
    /* memory faults stay with the emulator's own handler */
    if (host != SIGSEGV && host != SIGBUS) {
        sigaction(host, &act, NULL);
    }
    return old;
}

/* Push the kernel's signal frame and enter the handler. */
static void deliver(CPUZ8000State *env, int zsig)
{
    bool segmented = get_task_state(env_cpu(env))->info->segmented;
    uint32_t handler = handlers[zsig];
    uint32_t sp = (env->regs[15] - 6) & 0xffff;
    uint8_t *frame;
    bool ok;

    frame = zeus_data_ptr(env, (zeus_stack_ptr(env) & 0x7f0000) | sp, 6,
                          true);
    if (!frame) {
        zeus_die(TARGET_SIGSEGV);
    }
    /* a non-segmented program runs in segment 0x3f as the kernel sees it */
    stw_be_p(frame, segmented ? (env->pc >> 8) & 0x7f00 : 0x3f00);
    stw_be_p(frame + 2, env->pc & 0xffff);
    stw_be_p(frame + 4, env->fcw);
    env->regs[15] = sp;
    if (segmented) {
        env->pc = handler;
    } else {
        env->pc = (env->pc & 0xffff0000) | (handler & 0xffff);
    }
    if (zsig != TARGET_SIGILL && zsig != TARGET_SIGTRAP) {
        zeus_sig(zsig, 0, &ok);
    }
}

/* System call 0: return from a signal handler. */
void zeus_sigreturn(CPUZ8000State *env)
{
    bool segmented = get_task_state(env_cpu(env))->info->segmented;
    uint8_t *frame = zeus_data_ptr(env, zeus_stack_ptr(env), 6, false);

    if (!frame) {
        zeus_die(TARGET_SIGSEGV);
    }
    if (segmented) {
        env->pc = zeus_long_to_ptr(ldl_be_p(frame));
    } else {
        env->pc = (env->pc & 0xffff0000) | lduw_be_p(frame + 2);
    }
    env->fcw = (env->fcw & 0xff00) | (lduw_be_p(frame + 4) & 0x00fc);
    env->regs[15] = (env->regs[15] + 6) & 0xffff;
}

/* Deliver what arrived; called from the CPU loop between instructions. */
void zeus_process_signals(CPUZ8000State *env)
{
    TaskState *ts = get_task_state(env_cpu(env));

    if (ts->in_fpe) {
        return;         /* wait for the floating-point instruction to end */
    }
    ts->signal_pending = 0;
    for (int zsig = 1; zsig < TARGET_NSIG; zsig++) {
        if (pending[zsig]) {
            pending[zsig] = 0;
            if (handlers[zsig] > 1) {
                deliver(env, zsig);
            } else if (handlers[zsig] == 0) {
                zeus_die(zsig);
            }
        }
    }
}

/* A signal raised by the program's own action (a trap). */
void zeus_force_signal(CPUZ8000State *env, int zsig, const char *what)
{
    /* an attached debugger sees the trap first and may swallow it */
    if (!gdb_handlesig(env_cpu(env), zsig, NULL, NULL, 0)) {
        return;
    }
    if (handlers[zsig] > 1) {
        deliver(env, zsig);
        return;
    }
    gdb_signalled(env, zsig);
    fflush(stdout);
    fprintf(stderr, "qemu-" TARGET_NAME ": %s, pc %04x\n", what,
            env->pc & 0x7fffff);
    zeus_die(zsig);
}

static void die_from_signal(int sig)
{
    struct sigaction act = { .sa_handler = SIG_DFL };

    sigaction(sig, &act, NULL);
    raise(sig);
    _exit(128 + sig);
}

void cpu_loop_exit_sigsegv(CPUState *cpu, vaddr addr,
                           MMUAccessType access_type, bool maperr,
                           uintptr_t ra)
{
    get_task_state(cpu)->fault_addr = addr;
    cpu->exception_index = EXCP_Z8000_SEGTRAP;
    cpu_loop_exit_restore(cpu, ra);
}

void cpu_loop_exit_sigbus(CPUState *cpu, vaddr addr,
                          MMUAccessType access_type, uintptr_t ra)
{
    cpu_loop_exit_sigsegv(cpu, addr, access_type, false, ra);
}

static void host_fault_handler(int sig, siginfo_t *info, void *puc)
{
    CPUState *cpu = thread_cpu;
    host_sigcontext *uc = puc;
    uintptr_t host_addr = (uintptr_t)info->si_addr;
    bool is_valid = h2g_valid(host_addr);
    abi_ptr guest_addr = h2g_nocheck(host_addr);
    uintptr_t pc = host_signal_pc(uc);
    bool is_write = host_signal_write(info, uc);
    MMUAccessType access_type = adjust_signal_pc(&pc, is_write);

    /* A write to a page protected because it holds translated code. */
    if (sig == SIGSEGV && is_write && is_valid &&
        info->si_code == SEGV_ACCERR &&
        handle_sigsegv_accerr_write(cpu, host_signal_mask(uc), pc,
                                    guest_addr)) {
        return;
    }

    /* A fault that was not taken on behalf of the guest is a bug here. */
    if (!cpu || (access_type != MMU_INST_FETCH &&
                 !in_code_gen_buffer((void *)(pc - tcg_splitwx_diff)))) {
        die_from_signal(sig);
    }

    sigprocmask(SIG_SETMASK, host_signal_mask(uc), NULL);
    cpu_loop_exit_sigsegv(cpu, guest_addr, access_type, true, pc);
}

void zeus_signal_init(void)
{
    struct sigaction act;

#ifdef SIGRTMIN
    host_interrupt_signal = SIGRTMIN;
#else
    host_interrupt_signal = SIGUSR2;
#endif
    /* signals ignored when we were started stay ignored, and say so */
    for (int zsig = 1; zsig < TARGET_NSIG; zsig++) {
        int host = target_to_host_signal(zsig);
        struct sigaction old;

        if (host > 0 && sigaction(host, NULL, &old) == 0 &&
            old.sa_handler == SIG_IGN) {
            handlers[zsig] = 1;
        }
    }

    sigfillset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = host_fault_handler;
    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGBUS, &act, NULL);
}
