/*
 * Zilog Z8000 helpers: exceptions, control registers, block instructions
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/log.h"
#include "cpu.h"
#include "accel/tcg/cpu-ops.h"
#include "accel/tcg/cpu-loop.h"
#ifndef CONFIG_USER_ONLY
#include "exec/cputlb.h"
#endif
#include "exec/page-protection.h"
#include "exec/target_page.h"
#include "accel/tcg/cpu-ldst.h"
#include "exec/helper-proto.h"

#include "arith.c.inc"
#include "arith-wrap.c.inc"
#include "dab.c.inc"

/* ---- register file views ---- */

static inline uint32_t rb_get(CPUZ8000State *env, int n)
{
    return (n & 8) ? env->regs[n & 7] & 0xff : env->regs[n] >> 8;
}

static inline void rb_set(CPUZ8000State *env, int n, uint32_t v)
{
    v &= 0xff;
    if (n & 8) {
        env->regs[n & 7] = (env->regs[n & 7] & 0xff00) | v;
    } else {
        env->regs[n] = (env->regs[n] & 0x00ff) | (v << 8);
    }
}

static inline uint32_t rl_get(CPUZ8000State *env, int n)
{
    n &= 14;
    return (env->regs[n] << 16) | env->regs[n + 1];
}

/* ---- addresses ---- */

static inline uint32_t addr_add(uint32_t addr, uint32_t n)
{
    return (addr & 0xffff0000) | ((addr + n) & 0xffff);
}

static inline uint32_t segmented_addr(uint32_t v)
{
    return ((v & 0x7f000000) >> 8) | (v & 0xffff);
}

/*
 * The PC keeps bit 15 of the segment word it was loaded from (pc_b15);
 * these convert between the PC and its segmented long form.
 */
static inline uint32_t pc_to_long(CPUZ8000State *env)
{
    return ((env->pc & 0x007f0000) << 8) | (env->pc & 0xffff) |
           (env->pc_b15 ? 0x80000000 : 0);
}

static inline uint32_t pc_from_long(CPUZ8000State *env, uint32_t v)
{
    env->pc_b15 = v >> 31;
    return ((v & 0x7f000000) >> 8) | (v & 0xffff);
}

static inline uint32_t addr_from_reg(CPUZ8000State *env, int reg)
{
    if (z8000_segmented_mode(env)) {
        return segmented_addr(rl_get(env, reg));
    }
    return env->regs[reg];
}

static inline void add_to_addr_reg(CPUZ8000State *env, int reg, int n)
{
    if (z8000_segmented_mode(env)) {
        reg |= 1;
    }
    env->regs[reg] = (env->regs[reg] + n) & 0xffff;
}

/*
 * Data-space address presented to memory.  In non-segmented mode a Z8001
 * supplies the PC's segment number; split I&D programs add the data tag.
 */
static inline uint32_t adj(CPUZ8000State *env, uint32_t addr)
{
    if (!z8000_segmented_mode(env)) {
        return (addr & 0xffff) | (env->pc & 0x7f0000) | env->data_tag;
    }
    return (addr & 0x7fffff) | env->data_tag;
}

/* ---- memory ---- */

static uint32_t rdb(CPUZ8000State *env, uint32_t addr, uintptr_t ra)
{
    return cpu_ldub_mmuidx_ra(env, adj(env, addr), MMU_DATA_IDX, ra);
}

static uint32_t rdw(CPUZ8000State *env, uint32_t addr, uintptr_t ra)
{
    return cpu_lduw_be_mmuidx_ra(env, adj(env, addr) & ~1, MMU_DATA_IDX, ra);
}

static uint32_t rdl(CPUZ8000State *env, uint32_t addr, uintptr_t ra)
{
    uint32_t a = adj(env, addr) & ~1;
    uint32_t hi = cpu_lduw_be_mmuidx_ra(env, a, MMU_DATA_IDX, ra);

    return (hi << 16) |
           cpu_lduw_be_mmuidx_ra(env, addr_add(a, 2), MMU_DATA_IDX, ra);
}

static void wrb(CPUZ8000State *env, uint32_t addr, uint32_t v, uintptr_t ra)
{
    cpu_stb_mmuidx_ra(env, adj(env, addr), v, MMU_DATA_IDX, ra);
}

static void wrw(CPUZ8000State *env, uint32_t addr, uint32_t v, uintptr_t ra)
{
    cpu_stw_be_mmuidx_ra(env, adj(env, addr) & ~1, v, MMU_DATA_IDX, ra);
}

static void wrl(CPUZ8000State *env, uint32_t addr, uint32_t v, uintptr_t ra)
{
    uint32_t a = adj(env, addr) & ~1;

    cpu_stw_be_mmuidx_ra(env, a, v >> 16, MMU_DATA_IDX, ra);
    cpu_stw_be_mmuidx_ra(env, addr_add(a, 2), v & 0xffff, MMU_DATA_IDX, ra);
}

/* ---- stack ---- */

static inline int sp_reg(CPUZ8000State *env)
{
    return z8000_segmented_mode(env) ? 14 : 15;
}

G_GNUC_UNUSED static void pushw(CPUZ8000State *env, int reg, uint32_t v, uintptr_t ra)
{
    add_to_addr_reg(env, reg, -2);
    wrw(env, addr_from_reg(env, reg), v, ra);
}

G_GNUC_UNUSED static void pushl(CPUZ8000State *env, int reg, uint32_t v, uintptr_t ra)
{
    add_to_addr_reg(env, reg, -4);
    wrl(env, addr_from_reg(env, reg), v, ra);
}

static uint32_t popw(CPUZ8000State *env, int reg, uintptr_t ra)
{
    uint32_t v = rdw(env, addr_from_reg(env, reg), ra);

    add_to_addr_reg(env, reg, 2);
    return v;
}

static uint32_t popl(CPUZ8000State *env, int reg, uintptr_t ra)
{
    uint32_t v = rdl(env, addr_from_reg(env, reg), ra);

    add_to_addr_reg(env, reg, 4);
    return v;
}

/* ---- program status ---- */

void z8000_change_fcw(CPUZ8000State *env, uint32_t fcw)
{
    uint32_t tmp;

    fcw &= 0xffff;
    if ((fcw ^ env->fcw) & F_S_N) {
        tmp = env->regs[15];
        env->regs[15] = env->nspoff;
        env->nspoff = tmp;
    }
    if (env->segmented_cpu) {
        bool swap14 = false;

        if (fcw & F_S_N) {
            /* entering or staying in system mode */
            swap14 = !(env->fcw & F_S_N) || ((fcw ^ env->fcw) & F_SEG);
        } else {
            swap14 = (env->fcw & F_S_N) && (env->fcw & F_SEG);
        }
        if (swap14) {
            tmp = env->regs[14];
            env->regs[14] = env->nspseg;
            env->nspseg = tmp;
        }
    } else {
        fcw &= ~F_SEG;
    }
    env->fcw = fcw;
}

void HELPER(change_fcw)(CPUZ8000State *env, uint32_t fcw)
{
    z8000_change_fcw(env, fcw);
}

uint32_t HELPER(ldctl_rd)(CPUZ8000State *env, uint32_t ctl)
{
    switch (ctl) {
    case 2: return env->fcw;
    case 3: return env->refresh;
    /* the low bytes of PSAPSEG and PSAPOFF are not implemented */
    case 4: return env->psapseg & 0xff00;
    case 5: return env->psapoff & 0xff00;
    case 6: return env->nspseg;
    case 7: return env->nspoff;
    }
    return 0;
}

void HELPER(ldctl_wr)(CPUZ8000State *env, uint32_t ctl, uint32_t v)
{
    v &= 0xffff;
    switch (ctl) {
    case 2:
        /* FCW bits 10-8 and 1-0 are not implemented */
        z8000_change_fcw(env, v & 0xf8fc);
        break;
    case 3:
        env->refresh = v;
        break;
    case 4:
        env->psapseg = v;
        break;
    case 5:
        env->psapoff = v;
        break;
    case 6:
        env->nspseg = v;
        break;
    case 7:
        env->nspoff = v;
        break;
    }
}

/*
 * LDPS: load FCW and PC from memory.  keepseg selects whether the
 * non-segmented form preserves the PC segment.
 */
void HELPER(ldps)(CPUZ8000State *env, uint32_t addr, uint32_t keepseg)
{
    uintptr_t ra = GETPC();
    uint32_t fcw, pc;

    if (z8000_segmented_mode(env)) {
        fcw = rdw(env, addr + 2, ra);
        pc = pc_from_long(env, rdl(env, addr + 4, ra));
    } else {
        fcw = rdw(env, addr, ra);
        pc = rdw(env, (addr + 2) & 0xffff, ra);
        if (keepseg) {
            pc |= env->pc & 0xffff0000;
        }
    }
    env->pc = pc;
    z8000_change_fcw(env, fcw);
}

void HELPER(iret)(CPUZ8000State *env)
{
    uintptr_t ra = GETPC();
    uint32_t fcw, pc;

    popw(env, sp_reg(env), ra);         /* identifier word */
    fcw = popw(env, sp_reg(env), ra);
    if (z8000_segmented_mode(env)) {
        pc = pc_from_long(env, popl(env, sp_reg(env), ra));
    } else {
        pc = popw(env, sp_reg(env), ra);
    }
    env->pc = pc;
    z8000_change_fcw(env, fcw);
}

/* ---- exceptions ---- */

G_NORETURN void HELPER(raise_exception)(CPUZ8000State *env, uint32_t excp)
{
    CPUState *cs = env_cpu(env);

    cs->exception_index = excp;
    cpu_loop_exit(cs);
}

G_NORETURN void HELPER(halt)(CPUZ8000State *env)
{
    CPUState *cs = env_cpu(env);
    Z8000CPU *cpu = env_archcpu(env);

    if (cpu->io_ops && cpu->io_ops->halt) {
        cpu->io_ops->halt(cpu->io_opaque);
    }
    cs->halted = 1;
    cs->exception_index = EXCP_HLT;
    cpu_loop_exit(cs);
}

#ifndef CONFIG_USER_ONLY
static uint32_t psa_addr(CPUZ8000State *env)
{
    if (env->segmented_cpu) {
        return ((env->psapseg & 0x7f00) << 8) | (env->psapoff & 0xff00);
    }
    return env->psapoff & 0xff00;
}

void z8000_cpu_do_interrupt(CPUState *cs)
{
    CPUZ8000State *env = cpu_env(cs);
    int excp = cs->exception_index;
    uint32_t old_fcw = env->fcw;
    uint32_t mult = env->segmented_cpu ? 2 : 1;
    uint32_t vec, tag, new_fcw;
    static const uint8_t vec_off[] = {
        [EXCP_Z8000_EPU] = 0x04, [EXCP_Z8000_PRIV] = 0x08,
        [EXCP_Z8000_SC] = 0x0c, [EXCP_Z8000_SEGTRAP] = 0x10,
        [EXCP_Z8000_NMI] = 0x14, [EXCP_Z8000_NVI] = 0x18,
        [EXCP_Z8000_VI] = 0x1c,
    };

    cs->exception_index = -1;
    if (excp < EXCP_Z8000_EPU || excp > EXCP_Z8000_VI) {
        return;
    }
    tag = excp <= EXCP_Z8000_SC ? env->op0 : env->irq_vec;

    /* Program status is saved on the (segmented, on a Z8001) system stack. */
    z8000_change_fcw(env, old_fcw | F_S_N |
                     (env->segmented_cpu ? F_SEG : 0));
    if (env->segmented_cpu) {
        pushl(env, sp_reg(env), pc_to_long(env), 0);
    } else {
        pushw(env, sp_reg(env), env->pc & 0xffff, 0);
    }
    pushw(env, sp_reg(env), old_fcw, 0);
    pushw(env, sp_reg(env), tag, 0);

    vec = psa_addr(env) + mult * vec_off[excp];
    if (env->segmented_cpu) {
        new_fcw = rdw(env, vec + 2, 0);
        if (excp == EXCP_Z8000_VI) {
            vec = psa_addr(env) + mult * 0x1e + 2 * (env->irq_vec & 0xff);
            env->pc = pc_from_long(env, rdl(env, vec, 0));
        } else {
            env->pc = pc_from_long(env, rdl(env, vec + 4, 0));
        }
    } else {
        new_fcw = rdw(env, vec, 0);
        if (excp == EXCP_Z8000_VI) {
            vec = psa_addr(env) + 0x1e + 2 * (env->irq_vec & 0xff);
            env->pc = rdw(env, vec, 0);
        } else {
            env->pc = rdw(env, vec + 2, 0);
        }
    }
    z8000_change_fcw(env, new_fcw);
}

bool z8000_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    /* External interrupt delivery is not wired up yet. */
    return false;
}

hwaddr z8000_cpu_get_phys_addr_debug(CPUState *cs, vaddr addr)
{
    return addr & Z8000_PHYS_MASK;
}

bool z8000_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                        MMUAccessType access_type, int mmu_idx,
                        bool probe, uintptr_t retaddr)
{
    address &= TARGET_PAGE_MASK;
    tlb_set_page(cs, address, address & Z8000_PHYS_MASK,
                 PAGE_READ | PAGE_WRITE | PAGE_EXEC, mmu_idx,
                 TARGET_PAGE_SIZE);
    return true;
}

#endif /* !CONFIG_USER_ONLY */

/* ---- I/O ---- */

uint32_t HELPER(in)(CPUZ8000State *env, uint32_t port, uint32_t flags)
{
    Z8000CPU *cpu = env_archcpu(env);

    if (cpu->io_ops && cpu->io_ops->read) {
        return cpu->io_ops->read(cpu->io_opaque, port & 0xffff,
                                 flags & 1 ? 2 : 1, (flags >> 1) & 1);
    }
    return flags & 1 ? 0xffff : 0xff;
}

void HELPER(out)(CPUZ8000State *env, uint32_t port, uint32_t val,
                 uint32_t flags)
{
    Z8000CPU *cpu = env_archcpu(env);

    if (cpu->io_ops && cpu->io_ops->write) {
        cpu->io_ops->write(cpu->io_opaque, port & 0xffff,
                           val & (flags & 1 ? 0xffff : 0xff),
                           flags & 1 ? 2 : 1, (flags >> 1) & 1);
    }
}

/* ---- multi-register and block instructions ---- */

void HELPER(ldm)(CPUZ8000State *env, uint32_t addr, uint32_t reg,
                 uint32_t cnt, uint32_t store)
{
    uintptr_t ra = GETPC();
    int n = cnt;

    while (n-- >= 0) {
        if (store) {
            wrw(env, addr, env->regs[reg], ra);
        } else {
            env->regs[reg] = rdw(env, addr, ra);
        }
        addr = addr_add(addr, 2);
        reg = (reg + 1) & 15;
    }
}

static bool cond_true(CPUZ8000State *env, int cc)
{
    uint32_t f = env->fcw;
    bool c = f & F_C, z = f & F_Z, s = f & F_S, v = f & F_PV, r;

    switch (cc & 7) {
    default: r = false; break;
    case 1: r = v ^ s; break;
    case 2: r = z | (v ^ s); break;
    case 3: r = z | c; break;
    case 4: r = v; break;
    case 5: r = s; break;
    case 6: r = z; break;
    case 7: r = c; break;
    }
    return (cc & 8) ? !r : r;
}

static inline void set_flag(CPUZ8000State *env, uint32_t flag, bool on)
{
    env->fcw = on ? env->fcw | flag : env->fcw & ~flag;
}

/* Decrement a count register; returns true when it is still non-zero. */
static inline bool dec_count(CPUZ8000State *env, int reg)
{
    env->regs[reg] = (env->regs[reg] - 1) & 0xffff;
    return env->regs[reg] != 0;
}

/*
 * CPI/CPD/CPSI/CPSD and their repeating forms.
 * desc = first word | second word << 16.  Returns non-zero to repeat.
 */
uint32_t HELPER(blk_cp)(CPUZ8000State *env, uint32_t desc)
{
    uintptr_t ra = GETPC();
    uint32_t op0 = desc & 0xffff, op1 = desc >> 16;
    bool word = op0 & 0x0100;
    int kind = op0 & 15;
    int src = (op0 >> 4) & 15;
    int cc = op1 & 15, dst = (op1 >> 4) & 15, cnt = (op1 >> 8) & 15;
    int step = (word ? 2 : 1) * ((kind & 8) ? -1 : 1);
    bool string = kind & 2, repeat = kind & 4;
    uint32_t a, b;

    if (word) {
        a = string ? rdw(env, addr_from_reg(env, dst), ra) : env->regs[dst];
        b = rdw(env, addr_from_reg(env, src), ra);
        CPW(env, a, b);
    } else {
        a = string ? rdb(env, addr_from_reg(env, dst), ra) : rb_get(env, dst);
        b = rdb(env, addr_from_reg(env, src), ra);
        CPB(env, a, b);
    }
    set_flag(env, F_Z, cond_true(env, cc));
    add_to_addr_reg(env, src, step);
    if (string) {
        add_to_addr_reg(env, dst, step);
    }
    if (dec_count(env, cnt)) {
        set_flag(env, F_PV, false);
        return repeat && !(env->fcw & F_Z);
    }
    set_flag(env, F_PV, true);
    return 0;
}

/* LDI/LDD and their repeating forms. */
uint32_t HELPER(blk_ld)(CPUZ8000State *env, uint32_t desc)
{
    uintptr_t ra = GETPC();
    uint32_t op0 = desc & 0xffff, op1 = desc >> 16;
    bool word = op0 & 0x0100;
    int kind = op0 & 15;
    int src = (op0 >> 4) & 15;
    int cc = op1 & 15, dst = (op1 >> 4) & 15, cnt = (op1 >> 8) & 15;
    int step = (word ? 2 : 1) * ((kind & 8) ? -1 : 1);

    if (word) {
        wrw(env, addr_from_reg(env, dst),
            rdw(env, addr_from_reg(env, src), ra), ra);
    } else {
        wrb(env, addr_from_reg(env, dst),
            rdb(env, addr_from_reg(env, src), ra), ra);
    }
    add_to_addr_reg(env, src, step);
    add_to_addr_reg(env, dst, step);
    if (dec_count(env, cnt)) {
        env->fcw &= ~(F_PV | F_Z);
        return cc == 0;
    }
    env->fcw |= F_PV | F_Z;
    return 0;
}

/* TRIB/TRDB/TRTIB/TRTDB and their repeating forms. */
uint32_t HELPER(blk_tr)(CPUZ8000State *env, uint32_t desc)
{
    uintptr_t ra = GETPC();
    uint32_t op0 = desc & 0xffff, op1 = desc >> 16;
    int kind = op0 & 15;
    int dst = (op0 >> 4) & 15;
    int src = (op1 >> 4) & 15, cnt = (op1 >> 8) & 15;
    int step = (kind & 8) ? -1 : 1;
    bool test = kind & 2, repeat = kind & 4;
    uint32_t daddr = addr_from_reg(env, dst);
    uint32_t xlt = rdb(env, addr_add(addr_from_reg(env, src),
                                     rdb(env, daddr, ra)), ra);

    /* RH1 receives the translated byte after the pointer is stepped. */
    if (test) {
        set_flag(env, F_Z, !xlt);
        add_to_addr_reg(env, dst, step);
        rb_set(env, 1, xlt);
        if (dec_count(env, cnt)) {
            set_flag(env, F_PV, false);
            return repeat && !xlt;
        }
        set_flag(env, F_PV, true);
        return 0;
    }
    wrb(env, daddr, xlt, ra);
    add_to_addr_reg(env, dst, step);
    rb_set(env, 1, xlt);
    if (dec_count(env, cnt)) {
        set_flag(env, F_PV, false);
        return repeat;
    }
    set_flag(env, F_PV, true);
    return 0;
}

/* INI/IND/OUTI/OUTD, special variants and repeating forms. */
uint32_t HELPER(blk_io)(CPUZ8000State *env, uint32_t desc)
{
    uintptr_t ra = GETPC();
    uint32_t op0 = desc & 0xffff, op1 = desc >> 16;
    bool word = op0 & 0x0100;
    int kind = op0 & 15;
    int src = (op0 >> 4) & 15;
    int cc = op1 & 15, dst = (op1 >> 4) & 15, cnt = (op1 >> 8) & 15;
    int step = (word ? 2 : 1) * ((kind & 8) ? -1 : 1);
    uint32_t flags = (word ? 1 : 0) | ((kind & 1) ? 2 : 0);

    if (kind & 2) {
        /* output: port in RW(dst), data at @src */
        uint32_t v = word ? rdw(env, addr_from_reg(env, src), ra)
                          : rdb(env, addr_from_reg(env, src), ra);
        helper_out(env, env->regs[dst], v, flags);
        add_to_addr_reg(env, src, step);
    } else {
        uint32_t v = helper_in(env, env->regs[src], flags);
        if (word) {
            wrw(env, addr_from_reg(env, dst), v, ra);
        } else {
            wrb(env, addr_from_reg(env, dst), v, ra);
        }
        add_to_addr_reg(env, dst, step);
    }
    if (dec_count(env, cnt)) {
        env->fcw &= ~(F_PV | F_Z);
        return cc == 0;
    }
    env->fcw |= F_PV | F_Z;
    return 0;
}

void HELPER(rrdb)(CPUZ8000State *env, uint32_t a, uint32_t b)
{
    uint32_t ra_ = rb_get(env, a), tmp = ra_;

    rb_set(env, a, (ra_ >> 4) | (rb_get(env, b) << 4));
    rb_set(env, b, (rb_get(env, b) & 0xf0) | (tmp & 0x0f));
    env->fcw &= ~(F_Z | F_S);
    if (!rb_get(env, b)) {
        env->fcw |= F_Z;
    } else if (rb_get(env, b) & 0x80) {
        env->fcw |= F_S;
    }
}

void HELPER(rldb)(CPUZ8000State *env, uint32_t a, uint32_t b)
{
    uint32_t ra_ = rb_get(env, a), tmp = ra_;

    rb_set(env, a, (ra_ << 4) | (rb_get(env, b) & 0x0f));
    rb_set(env, b, (rb_get(env, b) & 0xf0) | (tmp >> 4));
    env->fcw &= ~(F_Z | F_S);
    if (!rb_get(env, b)) {
        env->fcw |= F_Z;
    } else if (rb_get(env, b) & 0x80) {
        env->fcw |= F_S;
    }
}

uint32_t HELPER(dab)(CPUZ8000State *env, uint32_t v)
{
    uint32_t idx = v & 0xff;
    uint8_t result;

    if (env->fcw & F_C) {
        idx |= 0x100;
    }
    if (env->fcw & F_H) {
        idx |= 0x200;
    }
    if (env->fcw & F_DA) {
        idx |= 0x400;
    }
    result = Z8000_dab[idx];
    CLR_CZS;
    CHK_XXXB_ZS;
    if (Z8000_dab[idx] & 0x100) {
        SET_C;
    }
    return result;
}

uint64_t HELPER(multl)(CPUZ8000State *env, uint32_t a, uint32_t b)
{
    return MULTL(env, a, b);
}

uint64_t HELPER(divl)(CPUZ8000State *env, uint64_t a, uint32_t b)
{
    return DIVL(env, a, b);
}
