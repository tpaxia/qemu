/*
 * host-signal.h: signal info dependent on the host architecture
 *
 * macOS on Apple silicon.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DARWIN_AARCH64_HOST_SIGNAL_H
#define DARWIN_AARCH64_HOST_SIGNAL_H

#include <sys/ucontext.h>

/* The third argument to a SA_SIGINFO handler is ucontext_t. */
typedef ucontext_t host_sigcontext;

static inline uintptr_t host_signal_pc(host_sigcontext *uc)
{
    return __darwin_arm_thread_state64_get_pc(uc->uc_mcontext->__ss);
}

static inline void host_signal_set_pc(host_sigcontext *uc, uintptr_t pc)
{
    __darwin_arm_thread_state64_set_pc_fptr(uc->uc_mcontext->__ss,
                                            (void *)pc);
}

static inline void *host_signal_mask(host_sigcontext *uc)
{
    return &uc->uc_sigmask;
}

static inline bool host_signal_write(siginfo_t *info, host_sigcontext *uc)
{
    uint32_t esr = uc->uc_mcontext->__es.__esr;

    /* For data aborts ESR.EC is 0b10010x: then bit 6 is the WnR bit */
    return extract32(esr, 27, 5) == 0x12 && extract32(esr, 6, 1) == 1;
}

#endif
