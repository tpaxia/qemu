/*
 * Zilog Z8000 (Z8001 segmented, Z8002 non-segmented) CPU
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef QEMU_Z8000_CPU_H
#define QEMU_Z8000_CPU_H

#include "cpu-qom.h"
#include "exec/cpu-common.h"
#include "exec/cpu-interrupt.h"

#define CPU_RESOLVING_TYPE TYPE_Z8000_CPU

/* Instruction fetch and data use separate MMU indexes. */
#define MMU_CODE_IDX 0
#define MMU_DATA_IDX 1
#ifdef CONFIG_USER_ONLY
#define MMU_USER_IDX MMU_DATA_IDX
#endif

/*
 * Guest virtual address layout:
 *   bits 15-0   offset
 *   bits 22-16  segment number
 *   bit 23      unused
 *   bit 24      data-space tag
 *   bit 25      system-space tag
 *
 * A program with separate instruction and data spaces has two memories at
 * the same segment:offset.  User-mode emulation has one flat address space
 * and no MMU, so data references carry Z8000_DATA_TAG when the CPU's
 * data_tag is set; program references (fetch, PC-relative loads) never do.
 */
#define Z8000_DATA_TAG  0x01000000
/*
 * User-mode emulation can run system-mode code (the operating system's
 * floating-point emulator) beside the program.  The real machine gives
 * system mode its own address translation; here that code lives at
 * addresses carrying Z8000_SYS_TAG: its PC has the bit set, and data_tag
 * is Z8000_SYS_TAG while it runs.
 */
#define Z8000_SYS_TAG   0x02000000
#define Z8000_PHYS_MASK 0x017fffff

/* Flag and control word */
#define F_SEG   0x8000  /* segmented mode (Z8001 only) */
#define F_S_N   0x4000  /* system / normal mode */
#define F_EPU   0x2000  /* extended processing unit present */
#define F_VIE   0x1000  /* vectored interrupt enable */
#define F_NVIE  0x0800  /* non-vectored interrupt enable */
#define F_C     0x0080
#define F_Z     0x0040
#define F_S     0x0020
#define F_PV    0x0010
#define F_DA    0x0008
#define F_H     0x0004

/* Exceptions, in the Program Status Area order */
enum {
    EXCP_Z8000_EPU = 1,     /* extended instruction trap */
    EXCP_Z8000_PRIV,        /* privileged instruction trap */
    EXCP_Z8000_SC,          /* system call */
    EXCP_Z8000_SEGTRAP,
    EXCP_Z8000_NMI,
    EXCP_Z8000_NVI,
    EXCP_Z8000_VI,
};

/* Translation block flags */
#define TB_FLAG_SEG  1
#define TB_FLAG_SYS  2
#define TB_FLAG_EPU  4
#define TB_FLAG_SPLIT 8   /* data references carry Z8000_DATA_TAG */
#define TB_FLAG_SYSSPACE 16  /* data references carry Z8000_SYS_TAG */
#define TB_FLAG_PCB15 32  /* bit 15 of the segment word the PC came from */

typedef struct CPUArchState {
    uint32_t regs[16];      /* R0-R15, 16 bits each */
    uint32_t pc;            /* segment << 16 | offset */
    uint32_t pc_b15;        /* bit 15 of the segment word the PC was loaded
                               from; the Z8001 keeps it and writes it back */
    uint32_t fcw;
    uint32_t psapseg;
    uint32_t psapoff;
    uint32_t refresh;
    uint32_t nspseg;        /* inactive (normal/system) stack pointer */
    uint32_t nspoff;
    uint32_t op0;           /* first word of a trapping instruction */
    uint32_t irq_vec;
    bool segmented_cpu;     /* true for the Z8001 */
    uint32_t data_tag;      /* 0, Z8000_DATA_TAG or Z8000_SYS_TAG */
} CPUZ8000State;

typedef struct Z8000IOOps {
    uint32_t (*read)(void *opaque, uint32_t port, int size, int special);
    void (*write)(void *opaque, uint32_t port, uint32_t val, int size,
                  int special);
    /* Called on HALT; may not return. */
    void (*halt)(void *opaque);
} Z8000IOOps;

struct ArchCPU {
    CPUState parent_obj;

    CPUZ8000State env;

    const Z8000IOOps *io_ops;
    void *io_opaque;
};

struct Z8000CPUClass {
    CPUClass parent_class;

    DeviceRealize parent_realize;
    ResettablePhases parent_phases;
    bool segmented;
};

static inline bool z8000_segmented_mode(const CPUZ8000State *env)
{
    return env->segmented_cpu && (env->fcw & F_SEG);
}

void z8000_change_fcw(CPUZ8000State *env, uint32_t fcw);

#ifndef CONFIG_USER_ONLY
void z8000_cpu_do_interrupt(CPUState *cpu);
bool z8000_cpu_exec_interrupt(CPUState *cpu, int int_req);
hwaddr z8000_cpu_get_phys_addr_debug(CPUState *cpu, vaddr addr);
bool z8000_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                        MMUAccessType access_type, int mmu_idx,
                        bool probe, uintptr_t retaddr);
#endif

void z8000_cpu_tcg_init(void);
void z8000_cpu_translate_code(CPUState *cs, TranslationBlock *tb,
                              int *max_insns, vaddr pc, void *host_pc);

#endif
