/*
 * ZEUS user-mode emulation: host signals
 *
 * Only memory faults are handled so far.  A write to a page holding
 * translated code is resolved by the translator; any other fault taken on
 * behalf of the guest ends the CPU loop iteration with a segment trap.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
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
    sigfillset(&act.sa_mask);
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = host_fault_handler;
    sigaction(SIGSEGV, &act, NULL);
    sigaction(SIGBUS, &act, NULL);
}
