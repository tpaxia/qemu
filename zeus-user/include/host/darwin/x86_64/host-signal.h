/*
 * host-signal.h: signal info dependent on the host architecture
 *
 * macOS on Intel processors.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DARWIN_X86_64_HOST_SIGNAL_H
#define DARWIN_X86_64_HOST_SIGNAL_H

#include <sys/ucontext.h>

/* The third argument to a SA_SIGINFO handler is ucontext_t. */
typedef ucontext_t host_sigcontext;

static inline uintptr_t host_signal_pc(host_sigcontext *uc)
{
    return uc->uc_mcontext->__ss.__rip;
}

static inline void host_signal_set_pc(host_sigcontext *uc, uintptr_t pc)
{
    uc->uc_mcontext->__ss.__rip = pc;
}

static inline void *host_signal_mask(host_sigcontext *uc)
{
    return &uc->uc_sigmask;
}

static inline bool host_signal_write(siginfo_t *info, host_sigcontext *uc)
{
    /* a page fault (trap 14) with the write bit in its error code */
    return uc->uc_mcontext->__es.__trapno == 0xe &&
           (uc->uc_mcontext->__es.__err & 0x2);
}

#endif
