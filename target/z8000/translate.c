/*
 * Zilog Z8000 translation
 *
 * The first opcode word is decoded by hand: bits 15-14 select the
 * addressing-mode group, bits 13-8 the operation, and the two low nibbles
 * registers or small immediates.  Segmented addresses are folded into one
 * flat 23-bit guest address (segment << 16 | offset).
 *
 * The Z8001 keeps bit 15 of the segment word the PC was loaded from and
 * writes it back wherever the PC is stored as a segmented long (LDAR,
 * CALL, CALR, traps).  That bit is separate CPU state (pc_b15), reflected
 * in the translation-block flags.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/qemu-print.h"
#include "tcg/tcg.h"
#include "cpu.h"
#include "exec/translation-block.h"
#include "tcg/tcg-op.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "exec/log.h"
#include "exec/translator.h"
#include "exec/target_page.h"

#define HELPER_H "helper.h"
#include "exec/helper-info.c.inc"
#undef  HELPER_H

#include "valid.c.inc"

static TCGv_i32 cpu_r[16];
static TCGv_i32 cpu_pc;
static TCGv_i32 cpu_fcw;

#define DISAS_EXIT   DISAS_TARGET_0  /* PC is set; return to the main loop */


enum { SZ_B, SZ_W, SZ_L };

typedef struct DisasContext {
    DisasContextBase base;
    CPUZ8000State *env;
    uint32_t pc;        /* address of the next word to fetch */
    uint32_t insn_pc;   /* address of the current instruction */
    uint32_t pcseg;     /* PC segment bits, used in non-segmented mode */
    uint32_t data_tag;  /* ORed into data-space addresses */
    uint16_t op0;
    bool addr_b15;      /* bit 15 of the last address operand's first word */
    bool pc_b15;        /* bit 15 of the segment word the PC came from */
    bool seg;           /* segmented mode */
    bool sys;           /* system mode */
    bool epu;           /* extended processing unit enabled */
} DisasContext;

typedef void gen_op2_fn(TCGv_i32, TCGv_env, TCGv_i32, TCGv_i32);
typedef void gen_cp_fn(TCGv_env, TCGv_i32, TCGv_i32);
typedef void gen_op1_fn(TCGv_i32, TCGv_env, TCGv_i32);
typedef void gen_test_fn(TCGv_env, TCGv_i32);

void z8000_cpu_tcg_init(void)
{
    static const char names[16][4] = {
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    };

    for (int i = 0; i < 16; i++) {
        cpu_r[i] = tcg_global_mem_new_i32(tcg_env,
                                          offsetof(CPUZ8000State, regs[i]),
                                          names[i]);
    }
    cpu_pc = tcg_global_mem_new_i32(tcg_env, offsetof(CPUZ8000State, pc),
                                    "pc");
    cpu_fcw = tcg_global_mem_new_i32(tcg_env, offsetof(CPUZ8000State, fcw),
                                     "fcw");
}

/* ---- instruction stream ---- */

static inline uint32_t addr_add(uint32_t addr, uint32_t n)
{
    return (addr & 0xffff0000) | ((addr + n) & 0xffff);
}

static uint16_t fetch(DisasContext *ctx)
{
    uint16_t w = translator_lduw_end(ctx->env, &ctx->base, ctx->pc, MO_BE);

    ctx->pc += 2;
    return w;
}

/* Address operand: one word, or one or two words in segmented mode. */
static uint32_t fetch_addr(DisasContext *ctx)
{
    uint32_t w = fetch(ctx);

    if (ctx->seg) {
        ctx->addr_b15 = w >> 15;
        if (w & 0x8000) {
            return ((w & 0x7f00) << 8) | fetch(ctx);
        }
        return ((w & 0x7f00) << 8) | (w & 0xff);
    }
    return w;
}

/* Address operand in register (segment word : offset word) format. */
static uint32_t fetch_addr_raw(DisasContext *ctx)
{
    uint32_t w = fetch(ctx);

    if (ctx->seg) {
        if (w & 0x8000) {
            return (w << 16) | fetch(ctx);
        }
        return (w << 16) | (w & 0xff);
    }
    return w;
}

/* ---- registers ---- */

static TCGv_i32 load_rb(int n)
{
    TCGv_i32 t = tcg_temp_new_i32();

    if (n & 8) {
        tcg_gen_ext8u_i32(t, cpu_r[n & 7]);
    } else {
        tcg_gen_shri_i32(t, cpu_r[n], 8);
    }
    return t;
}

static void store_rb(int n, TCGv_i32 v)
{
    if (n & 8) {
        tcg_gen_deposit_i32(cpu_r[n & 7], cpu_r[n & 7], v, 0, 8);
    } else {
        tcg_gen_deposit_i32(cpu_r[n], cpu_r[n], v, 8, 8);
    }
}

static TCGv_i32 load_rw(int n)
{
    TCGv_i32 t = tcg_temp_new_i32();

    tcg_gen_mov_i32(t, cpu_r[n]);
    return t;
}

static void store_rw(int n, TCGv_i32 v)
{
    tcg_gen_ext16u_i32(cpu_r[n], v);
}

static TCGv_i32 load_rl(int n)
{
    TCGv_i32 t = tcg_temp_new_i32();

    n &= 14;
    tcg_gen_shli_i32(t, cpu_r[n], 16);
    tcg_gen_or_i32(t, t, cpu_r[n + 1]);
    return t;
}

static void store_rl(int n, TCGv_i32 v)
{
    TCGv_i32 hi = tcg_temp_new_i32();

    n &= 14;
    tcg_gen_shri_i32(hi, v, 16);
    tcg_gen_ext16u_i32(cpu_r[n + 1], v);
    tcg_gen_mov_i32(cpu_r[n], hi);
}

static TCGv_i32 load_reg(int size, int n)
{
    switch (size) {
    case SZ_B:
        return load_rb(n);
    case SZ_W:
        return load_rw(n);
    default:
        return load_rl(n);
    }
}

static void store_reg(int size, int n, TCGv_i32 v)
{
    switch (size) {
    case SZ_B:
        store_rb(n, v);
        break;
    case SZ_W:
        store_rw(n, v);
        break;
    default:
        store_rl(n, v);
        break;
    }
}

/* ---- effective addresses ---- */

/* Address held in a register (pair, in segmented mode). */
static TCGv_i32 ea_reg(DisasContext *ctx, int reg)
{
    TCGv_i32 a = tcg_temp_new_i32();

    if (ctx->seg) {
        tcg_gen_andi_i32(a, cpu_r[reg & 14], 0x7f00);
        tcg_gen_shli_i32(a, a, 8);
        tcg_gen_or_i32(a, a, cpu_r[(reg & 14) | 1]);
    } else {
        tcg_gen_ori_i32(a, cpu_r[reg], ctx->pcseg);
    }
    return a;
}

/* base with a 16-bit offset added, wrapping within the segment. */
static TCGv_i32 ea_add(TCGv_i32 base, TCGv_i32 off)
{
    TCGv_i32 t = tcg_temp_new_i32();

    tcg_gen_add_i32(t, base, off);
    tcg_gen_deposit_i32(t, base, t, 0, 16);
    return t;
}

static uint32_t const_ea(DisasContext *ctx, uint32_t addr)
{
    if (!ctx->seg) {
        return (addr & 0xffff) | ctx->pcseg;
    }
    return addr & 0x7fffff;
}

/* Direct address. */
static TCGv_i32 ea_da(DisasContext *ctx, uint32_t addr)
{
    TCGv_i32 a = tcg_temp_new_i32();

    tcg_gen_movi_i32(a, const_ea(ctx, addr));
    return a;
}

/* Indexed address: direct address plus a 16-bit register. */
static TCGv_i32 ea_x(DisasContext *ctx, uint32_t addr, int reg)
{
    TCGv_i32 a = tcg_temp_new_i32();

    addr = const_ea(ctx, addr);
    tcg_gen_addi_i32(a, cpu_r[reg], addr & 0xffff);
    tcg_gen_andi_i32(a, a, 0xffff);
    tcg_gen_ori_i32(a, a, addr & 0xffff0000);
    return a;
}

/* ---- memory ---- */

/*
 * Address actually presented to memory: data-space references of a split
 * I&D program carry the data tag; program-space references do not.
 */
static TCGv_i32 mem_addr(DisasContext *ctx, TCGv_i32 addr, int mmu, bool even)
{
    TCGv_i32 a = tcg_temp_new_i32();

    if (even) {
        tcg_gen_andi_i32(a, addr, ~1);
    } else {
        tcg_gen_mov_i32(a, addr);
    }
    if (mmu == MMU_DATA_IDX && ctx->data_tag) {
        tcg_gen_ori_i32(a, a, ctx->data_tag);
    }
    return a;
}

static void gen_ld(DisasContext *ctx, int size, TCGv_i32 val, TCGv_i32 addr,
                   int mmu)
{
    TCGv_i32 a = mem_addr(ctx, addr, mmu, size != SZ_B);
    TCGv_i32 lo;

    switch (size) {
    case SZ_B:
        tcg_gen_qemu_ld_i32(val, a, mmu, MO_UB);
        break;
    case SZ_W:
        tcg_gen_qemu_ld_i32(val, a, mmu, MO_BEUW);
        break;
    default:
        lo = tcg_temp_new_i32();
        tcg_gen_qemu_ld_i32(val, a, mmu, MO_BEUW);
        tcg_gen_qemu_ld_i32(lo, ea_add(a, tcg_constant_i32(2)), mmu, MO_BEUW);
        tcg_gen_shli_i32(val, val, 16);
        tcg_gen_or_i32(val, val, lo);
        break;
    }
}

static void gen_st(DisasContext *ctx, int size, TCGv_i32 val, TCGv_i32 addr,
                   int mmu)
{
    TCGv_i32 a = mem_addr(ctx, addr, mmu, size != SZ_B);
    TCGv_i32 hi;

    switch (size) {
    case SZ_B:
        tcg_gen_qemu_st_i32(val, a, mmu, MO_UB);
        break;
    case SZ_W:
        tcg_gen_qemu_st_i32(val, a, mmu, MO_BEUW);
        break;
    default:
        hi = tcg_temp_new_i32();
        tcg_gen_shri_i32(hi, val, 16);
        tcg_gen_qemu_st_i32(hi, a, mmu, MO_BEUW);
        tcg_gen_qemu_st_i32(val, ea_add(a, tcg_constant_i32(2)), mmu,
                            MO_BEUW);
        break;
    }
}

/* ---- operands ---- */

enum { K_IM, K_R, K_MEM };

typedef struct Operand {
    int kind;
    int reg;
    TCGv_i32 addr;
} Operand;

/*
 * Decode the operand selected by the mode group and a register nibble:
 * group 0 is IR (IM when the nibble is zero), group 1 is X (DA when the
 * nibble is zero) and group 2 is a register.
 */
static void decode_operand(DisasContext *ctx, int mode, int nib, Operand *o)
{
    uint32_t addr;

    o->reg = nib;
    o->addr = NULL;
    switch (mode) {
    case 0:
        if (nib == 0) {
            o->kind = K_IM;
        } else {
            o->kind = K_MEM;
            o->addr = ea_reg(ctx, nib);
        }
        break;
    case 1:
        addr = fetch_addr(ctx);
        o->kind = K_MEM;
        o->addr = nib ? ea_x(ctx, addr, nib) : ea_da(ctx, addr);
        break;
    default:
        o->kind = K_R;
        break;
    }
}

static TCGv_i32 fetch_imm(DisasContext *ctx, int size)
{
    uint32_t v;

    switch (size) {
    case SZ_B:
        v = fetch(ctx) & 0xff;
        break;
    case SZ_W:
        v = fetch(ctx);
        break;
    default:
        v = fetch(ctx) << 16;
        v |= fetch(ctx);
        break;
    }
    return tcg_constant_i32(v);
}

static TCGv_i32 operand_load(DisasContext *ctx, Operand *o, int size)
{
    TCGv_i32 v;

    switch (o->kind) {
    case K_IM:
        return fetch_imm(ctx, size);
    case K_R:
        return load_reg(size, o->reg);
    default:
        v = tcg_temp_new_i32();
        gen_ld(ctx, size, v, o->addr, MMU_DATA_IDX);
        return v;
    }
}

static void operand_store(DisasContext *ctx, Operand *o, int size, TCGv_i32 v)
{
    if (o->kind == K_R) {
        store_reg(size, o->reg, v);
    } else if (o->kind == K_MEM) {
        gen_st(ctx, size, v, o->addr, MMU_DATA_IDX);
    }
}

/* ---- stack ---- */

static inline int sp_reg(DisasContext *ctx)
{
    return ctx->seg ? 14 : 15;
}

static void gen_adjust_ptr(DisasContext *ctx, int reg, int n)
{
    int r = ctx->seg ? (reg | 1) : reg;

    tcg_gen_addi_i32(cpu_r[r], cpu_r[r], n);
    tcg_gen_ext16u_i32(cpu_r[r], cpu_r[r]);
}

static void gen_push(DisasContext *ctx, int size, int reg, TCGv_i32 val)
{
    gen_adjust_ptr(ctx, reg, size == SZ_L ? -4 : -2);
    gen_st(ctx, size, val, ea_reg(ctx, reg), MMU_DATA_IDX);
}

static TCGv_i32 gen_pop(DisasContext *ctx, int size, int reg)
{
    TCGv_i32 v = tcg_temp_new_i32();

    gen_ld(ctx, size, v, ea_reg(ctx, reg), MMU_DATA_IDX);
    gen_adjust_ptr(ctx, reg, size == SZ_L ? 4 : 2);
    return v;
}

/* ---- control flow ---- */

static void gen_goto_tb(DisasContext *ctx, int slot, uint32_t dest)
{
    if (translator_use_goto_tb(&ctx->base, dest)) {
        tcg_gen_goto_tb(slot);
        tcg_gen_movi_i32(cpu_pc, dest);
        tcg_gen_exit_tb(ctx->base.tb, slot);
    } else {
        tcg_gen_movi_i32(cpu_pc, dest);
        tcg_gen_lookup_and_goto_ptr();
    }
    ctx->base.is_jmp = DISAS_NORETURN;
}

static void gen_jump_dyn(DisasContext *ctx, TCGv_i32 target)
{
    tcg_gen_mov_i32(cpu_pc, target);
    tcg_gen_lookup_and_goto_ptr();
    ctx->base.is_jmp = DISAS_NORETURN;
}

static void gen_set_pc_b15(TCGv_i32 b15)
{
    tcg_gen_st_i32(b15, tcg_env, offsetof(CPUZ8000State, pc_b15));
}

/*
 * Jump to a constant address, loading the PC's segment-word bit 15.  A
 * change of that bit changes the translation-block flags, so the block
 * cannot be chained directly.
 */
static void gen_jump_const(DisasContext *ctx, int slot, uint32_t dest,
                           bool b15)
{
    if (b15 == ctx->pc_b15) {
        gen_goto_tb(ctx, slot, dest);
    } else {
        gen_set_pc_b15(tcg_constant_i32(b15));
        gen_jump_dyn(ctx, tcg_constant_i32(dest));
    }
}

/*
 * A constant PC-relative jump target: the segment comes from the current
 * PC, which addr already carries.
 */
static uint32_t jump_target(DisasContext *ctx, uint32_t addr)
{
    if (ctx->seg) {
        return addr;
    }
    return (ctx->pc & 0xffff0000) | (addr & 0xffff);
}

/* Jump target given by an address operand just read with fetch_addr(). */
static uint32_t jump_target_addr(DisasContext *ctx, uint32_t addr)
{
    if (ctx->seg) {
        return (addr & 0x7fffff) | (ctx->pc & Z8000_SYS_TAG);
    }
    return (ctx->pc & 0xffff0000) | (addr & 0xffff);
}

/* The segment-word bit 15 the PC takes from an address operand. */
static bool jump_b15_addr(DisasContext *ctx)
{
    return ctx->seg ? ctx->addr_b15 : ctx->pc_b15;
}

/*
 * Jump target held in a register (pair, in segmented mode); also loads the
 * PC's segment-word bit 15 from the pair.
 */
static TCGv_i32 jump_reg(DisasContext *ctx, int reg)
{
    TCGv_i32 a = tcg_temp_new_i32();

    if (ctx->seg) {
        tcg_gen_shri_i32(a, cpu_r[reg & 14], 15);
        gen_set_pc_b15(a);
        tcg_gen_andi_i32(a, cpu_r[reg & 14], 0x7f00);
        tcg_gen_shli_i32(a, a, 8);
        tcg_gen_or_i32(a, a, cpu_r[(reg & 14) | 1]);
        tcg_gen_ori_i32(a, a, ctx->pc & Z8000_SYS_TAG);
    } else {
        tcg_gen_ori_i32(a, cpu_r[reg], ctx->pc & 0xffff0000);
    }
    return a;
}

/* Jump target given by an indexed address operand. */
static TCGv_i32 jump_x(DisasContext *ctx, uint32_t addr, int reg)
{
    TCGv_i32 a = ea_x(ctx, addr, reg);

    if (ctx->seg) {
        gen_set_pc_b15(tcg_constant_i32(ctx->addr_b15));
        tcg_gen_ori_i32(a, a, ctx->pc & Z8000_SYS_TAG);
    }
    return a;
}

static void gen_trap(DisasContext *ctx, int excp, uint32_t pc)
{
    tcg_gen_movi_i32(cpu_pc, pc);
    tcg_gen_st_i32(tcg_constant_i32(ctx->op0), tcg_env,
                   offsetof(CPUZ8000State, op0));
    gen_helper_raise_exception(tcg_env, tcg_constant_i32(excp));
    ctx->base.is_jmp = DISAS_NORETURN;
}

/* Privileged instructions trap in normal mode before fetching operands. */
static bool check_priv(DisasContext *ctx)
{
    if (!ctx->sys) {
        gen_trap(ctx, EXCP_Z8000_PRIV, ctx->insn_pc + 2);
        return false;
    }
    return true;
}

static void gen_ext_insn(DisasContext *ctx)
{
    if (!ctx->epu) {
        gen_trap(ctx, EXCP_Z8000_EPU, ctx->insn_pc + 2);
    }
}

static void gen_sync_pc(DisasContext *ctx)
{
    tcg_gen_movi_i32(cpu_pc, ctx->pc);
}

static void gen_exit(DisasContext *ctx)
{
    tcg_gen_exit_tb(NULL, 0);
    ctx->base.is_jmp = DISAS_NORETURN;
}

/* Evaluate a condition code into 0 or 1. */
static TCGv_i32 gen_cond(int cc)
{
    TCGv_i32 t = tcg_temp_new_i32();
    TCGv_i32 u = tcg_temp_new_i32();

    switch (cc & 7) {
    case 0:
        tcg_gen_movi_i32(t, 0);
        break;
    case 1: /* PV ^ S */
        tcg_gen_shri_i32(t, cpu_fcw, 4);
        tcg_gen_shri_i32(u, cpu_fcw, 5);
        tcg_gen_xor_i32(t, t, u);
        break;
    case 2: /* Z | (PV ^ S) */
        tcg_gen_shri_i32(t, cpu_fcw, 4);
        tcg_gen_shri_i32(u, cpu_fcw, 5);
        tcg_gen_xor_i32(t, t, u);
        tcg_gen_shri_i32(u, cpu_fcw, 6);
        tcg_gen_or_i32(t, t, u);
        break;
    case 3: /* Z | C */
        tcg_gen_shri_i32(t, cpu_fcw, 6);
        tcg_gen_shri_i32(u, cpu_fcw, 7);
        tcg_gen_or_i32(t, t, u);
        break;
    case 4:
        tcg_gen_shri_i32(t, cpu_fcw, 4);
        break;
    case 5:
        tcg_gen_shri_i32(t, cpu_fcw, 5);
        break;
    case 6:
        tcg_gen_shri_i32(t, cpu_fcw, 6);
        break;
    case 7:
        tcg_gen_shri_i32(t, cpu_fcw, 7);
        break;
    }
    tcg_gen_andi_i32(t, t, 1);
    if (cc & 8) {
        tcg_gen_xori_i32(t, t, 1);
    }
    return t;
}

/* Conditional branch to a constant address. */
static void gen_branch_cc(DisasContext *ctx, int cc, uint32_t dest, bool b15)
{
    TCGLabel *skip;

    if (cc == 0) {
        return;
    }
    if (cc == 8) {
        gen_jump_const(ctx, 0, dest, b15);
        return;
    }
    skip = gen_new_label();
    tcg_gen_brcondi_i32(TCG_COND_EQ, gen_cond(cc), 0, skip);
    gen_jump_const(ctx, 0, dest, b15);
    gen_set_label(skip);
    gen_goto_tb(ctx, 1, ctx->pc);
}

/* Return address in the form pushed by CALL/CALR. */
static void gen_push_pc(DisasContext *ctx)
{
    if (ctx->seg) {
        uint32_t v = ((ctx->pc & 0x7f0000) << 8) | (ctx->pc & 0xffff) |
                     (ctx->pc_b15 ? 0x80000000 : 0);
        gen_push(ctx, SZ_L, sp_reg(ctx), tcg_constant_i32(v));
    } else {
        gen_push(ctx, SZ_W, sp_reg(ctx), tcg_constant_i32(ctx->pc & 0xffff));
    }
}

/* Finish a block instruction: repeat it or fall through. */
static void gen_block_end(DisasContext *ctx, TCGv_i32 repeat)
{
    TCGLabel *again = gen_new_label();

    tcg_gen_brcondi_i32(TCG_COND_NE, repeat, 0, again);
    gen_goto_tb(ctx, 0, ctx->pc);
    gen_set_label(again);
    gen_goto_tb(ctx, 1, ctx->insn_pc);
}

/* ---- flag helpers ---- */

static void gen_set_flag_bit(TCGv_i32 bit, int pos)
{
    tcg_gen_deposit_i32(cpu_fcw, cpu_fcw, bit, pos, 1);
}

static int size_bits(int size)
{
    return size == SZ_B ? 8 : size == SZ_W ? 16 : 32;
}

/* ---- instruction groups ---- */

/* COM/NEG/TEST/TSET/CLR and the immediate CP/LD forms of the 0C/0D group. */
static void gen_unary(DisasContext *ctx, int sub, int size, Operand *o)
{
    static gen_op1_fn * const com[2] = { gen_helper_comb, gen_helper_comw };
    static gen_op1_fn * const neg[2] = { gen_helper_negb, gen_helper_negw };
    static gen_test_fn * const test[2] = {
        gen_helper_testb, gen_helper_testw
    };
    static gen_cp_fn * const cp[2] = { gen_helper_cpb, gen_helper_cpw };
    TCGv_i32 v, r;

    switch (sub) {
    case 0:
        v = operand_load(ctx, o, size);
        r = tcg_temp_new_i32();
        com[size](r, tcg_env, v);
        operand_store(ctx, o, size, r);
        break;
    case 1:
        v = operand_load(ctx, o, size);
        cp[size](tcg_env, v, fetch_imm(ctx, size));
        break;
    case 2:
        v = operand_load(ctx, o, size);
        r = tcg_temp_new_i32();
        neg[size](r, tcg_env, v);
        operand_store(ctx, o, size, r);
        break;
    case 4:
        v = operand_load(ctx, o, size);
        test[size](tcg_env, v);
        break;
    case 5:
        operand_store(ctx, o, size, fetch_imm(ctx, size));
        break;
    case 6:
        v = operand_load(ctx, o, size);
        r = tcg_temp_new_i32();
        tcg_gen_shri_i32(r, v, size_bits(size) - 1);
        gen_set_flag_bit(r, 5);
        operand_store(ctx, o, size,
                      tcg_constant_i32(size == SZ_B ? 0xff : 0xffff));
        break;
    case 8:
        operand_store(ctx, o, size, tcg_constant_i32(0));
        break;
    }
}

/* RES/SET/BIT with a mask in a temporary. */
static void gen_bitop(DisasContext *ctx, int op, int size, Operand *o,
                      TCGv_i32 mask)
{
    TCGv_i32 v = operand_load(ctx, o, size);
    TCGv_i32 t = tcg_temp_new_i32();

    switch (op) {
    case 0: /* RES */
        tcg_gen_andc_i32(t, v, mask);
        operand_store(ctx, o, size, t);
        break;
    case 1: /* SET */
        tcg_gen_or_i32(t, v, mask);
        operand_store(ctx, o, size, t);
        break;
    default: /* BIT */
        tcg_gen_and_i32(t, v, mask);
        tcg_gen_andi_i32(t, t, size == SZ_B ? 0xff : 0xffff);
        tcg_gen_setcondi_i32(TCG_COND_EQ, t, t, 0);
        gen_set_flag_bit(t, 6);
        break;
    }
}

/* LDA with a 16-bit index: copy the base pointer, then add to the offset. */
static void gen_lda_based(DisasContext *ctx, int dst, int src, TCGv_i32 idx)
{
    if (ctx->seg) {
        TCGv_i32 hi = load_rw(src & 14);
        TCGv_i32 lo = load_rw((src & 14) | 1);

        tcg_gen_mov_i32(cpu_r[dst & 14], hi);
        tcg_gen_mov_i32(cpu_r[(dst & 14) | 1], lo);
        tcg_gen_add_i32(cpu_r[dst | 1], cpu_r[dst | 1], idx);
        tcg_gen_ext16u_i32(cpu_r[dst | 1], cpu_r[dst | 1]);
    } else {
        TCGv_i32 t = tcg_temp_new_i32();

        tcg_gen_add_i32(t, cpu_r[src], idx);
        tcg_gen_ext16u_i32(cpu_r[dst], t);
    }
}

/* Shifts and rotates of the B2 (byte) and B3 (word and long) groups. */
static void gen_shift(DisasContext *ctx, bool word, int reg, int sub)
{
    static gen_op2_fn * const rot[2][4] = {
        { gen_helper_rlb, gen_helper_rrb, gen_helper_rlcb, gen_helper_rrcb },
        { gen_helper_rlw, gen_helper_rrw, gen_helper_rlcw, gen_helper_rrcw },
    };
    /* [arith][size][0 = left, 1 = right, 2 = dynamic] */
    static gen_op2_fn * const sh[2][3][3] = {
        {
            { gen_helper_sllb, gen_helper_srlb, gen_helper_sdlb },
            { gen_helper_sllw, gen_helper_srlw, gen_helper_sdlw },
            { gen_helper_slll, gen_helper_srll, gen_helper_sdll },
        },
        {
            { gen_helper_slab, gen_helper_srab, gen_helper_sdab },
            { gen_helper_slaw, gen_helper_sraw, gen_helper_sdaw },
            { gen_helper_slal, gen_helper_sral, gen_helper_sdal },
        },
    };
    TCGv_i32 r = tcg_temp_new_i32();
    TCGv_i32 v;
    int size, arith;
    uint16_t w;

    if (!(sub & 1)) {
        size = word ? SZ_W : SZ_B;
        v = load_reg(size, reg);
        rot[word][sub >> 2](r, tcg_env, v, tcg_constant_i32(sub & 2));
        store_reg(size, reg, r);
        return;
    }

    size = word ? ((sub & 4) ? SZ_L : SZ_W) : SZ_B;
    arith = (sub & 8) ? 1 : 0;
    v = load_reg(size, reg);
    w = fetch(ctx);
    if (sub & 2) {
        /* dynamic count in a word register */
        sh[arith][size][2](r, tcg_env, v, cpu_r[(w >> 8) & 15]);
    } else if (size == SZ_B) {
        uint8_t imm = w & 0xff;

        if (imm & 0x80) {
            sh[arith][size][1](r, tcg_env, v,
                               tcg_constant_i32((uint8_t)-(int8_t)imm));
        } else {
            sh[arith][size][0](r, tcg_env, v, tcg_constant_i32(imm));
        }
    } else {
        if (w & 0x8000) {
            sh[arith][size][1](r, tcg_env, v,
                               tcg_constant_i32((uint8_t)-(int16_t)w));
        } else {
            sh[arith][size][0](r, tcg_env, v, tcg_constant_i32((uint8_t)w));
        }
    }
    store_reg(size, reg, r);
}

/* Block instructions implemented by a helper returning "repeat". */
static void gen_block(DisasContext *ctx,
                      void (*fn)(TCGv_i32, TCGv_env, TCGv_i32))
{
    uint32_t desc = ctx->op0 | (fetch(ctx) << 16);
    TCGv_i32 rep = tcg_temp_new_i32();

    gen_sync_pc(ctx);
    fn(rep, tcg_env, tcg_constant_i32(desc));
    gen_block_end(ctx, rep);
}

/* The dyadic operations shared by all three addressing-mode groups. */
static bool gen_dyadic(DisasContext *ctx, int mode, int op6, int n2, int n3)
{
    static gen_op2_fn * const arith[12] = {
        gen_helper_addb, gen_helper_addw, gen_helper_subb, gen_helper_subw,
        gen_helper_orb, gen_helper_orw, gen_helper_andb, gen_helper_andw,
        gen_helper_xorb, gen_helper_xorw, NULL, NULL,
    };
    Operand o;
    TCGv_i32 s, d, r;
    TCGv_i64 q;

    switch (op6) {
    case 0x00 ... 0x09:
        decode_operand(ctx, mode, n2, &o);
        s = operand_load(ctx, &o, op6 & 1);
        d = load_reg(op6 & 1, n3);
        r = tcg_temp_new_i32();
        arith[op6](r, tcg_env, d, s);
        store_reg(op6 & 1, n3, r);
        return true;
    case 0x0a: /* CPB */
    case 0x0b: /* CP */
        decode_operand(ctx, mode, n2, &o);
        s = operand_load(ctx, &o, op6 & 1);
        d = load_reg(op6 & 1, n3);
        if (op6 & 1) {
            gen_helper_cpw(tcg_env, d, s);
        } else {
            gen_helper_cpb(tcg_env, d, s);
        }
        return true;
    case 0x10: /* CPL */
        decode_operand(ctx, mode, n2, &o);
        s = operand_load(ctx, &o, SZ_L);
        gen_helper_cpl(tcg_env, load_rl(n3), s);
        return true;
    case 0x12: /* SUBL */
    case 0x16: /* ADDL */
        decode_operand(ctx, mode, n2, &o);
        s = operand_load(ctx, &o, SZ_L);
        r = tcg_temp_new_i32();
        if (op6 == 0x12) {
            gen_helper_subl(r, tcg_env, load_rl(n3), s);
        } else {
            gen_helper_addl(r, tcg_env, load_rl(n3), s);
        }
        store_rl(n3, r);
        return true;
    case 0x14: /* LDL */
        decode_operand(ctx, mode, n2, &o);
        store_rl(n3, operand_load(ctx, &o, SZ_L));
        return true;
    case 0x18: /* MULTL */
        decode_operand(ctx, mode, n2, &o);
        s = operand_load(ctx, &o, SZ_L);
        q = tcg_temp_new_i64();
        n3 &= 12;      /* quad register */
        gen_helper_multl(q, tcg_env, load_rl(n3 + 2), s);
        r = tcg_temp_new_i32();
        d = tcg_temp_new_i32();
        tcg_gen_extr_i64_i32(r, d, q);
        store_rl(n3, d);
        store_rl(n3 + 2, r);
        return true;
    case 0x19: /* MULT */
        decode_operand(ctx, mode, n2, &o);
        s = operand_load(ctx, &o, SZ_W);
        r = tcg_temp_new_i32();
        gen_helper_multw(r, tcg_env, cpu_r[(n3 & 14) | 1], s);
        store_rl(n3, r);
        return true;
    case 0x1a: /* DIVL */
        decode_operand(ctx, mode, n2, &o);
        s = operand_load(ctx, &o, SZ_L);
        q = tcg_temp_new_i64();
        n3 &= 12;      /* quad register */
        tcg_gen_concat_i32_i64(q, load_rl(n3 + 2), load_rl(n3));
        gen_helper_divl(q, tcg_env, q, s);
        r = tcg_temp_new_i32();
        d = tcg_temp_new_i32();
        tcg_gen_extr_i64_i32(r, d, q);
        store_rl(n3, d);
        store_rl(n3 + 2, r);
        return true;
    case 0x1b: /* DIV */
        decode_operand(ctx, mode, n2, &o);
        s = operand_load(ctx, &o, SZ_W);
        r = tcg_temp_new_i32();
        gen_helper_divw(r, tcg_env, load_rl(n3), s);
        store_rl(n3, r);
        return true;
    case 0x20: /* LDB */
    case 0x21: /* LD */
        decode_operand(ctx, mode, n2, &o);
        store_reg(op6 & 1, n3, operand_load(ctx, &o, op6 & 1));
        return true;
    }
    return false;
}

/* Register-only group (first byte 0x80-0xBF) entries that are not dyadic. */
static void gen_group2(DisasContext *ctx, int op6, int n2, int n3)
{
    static gen_op2_fn * const adc[4] = {
        gen_helper_adcb, gen_helper_adcw, gen_helper_sbcb, gen_helper_sbcw,
    };
    Operand o = { .kind = K_R, .reg = n2 };
    TCGv_i32 v, t, r;
    int size = op6 & 1;

    switch (op6) {
    case 0x0c: /* byte unary, LDCTLB */
        if (n3 == 1) {
            v = tcg_temp_new_i32();
            tcg_gen_andi_i32(v, cpu_fcw, 0xfc);
            store_rb(n2, v);
        } else if (n3 == 9) {
            v = load_rb(n2);
            tcg_gen_andi_i32(v, v, 0xfc);
            tcg_gen_andi_i32(cpu_fcw, cpu_fcw, ~0xfc);
            tcg_gen_or_i32(cpu_fcw, cpu_fcw, v);
        } else {
            gen_unary(ctx, n3, SZ_B, &o);
        }
        break;
    case 0x0d: /* word unary, flag manipulation, NOP */
        switch (n3) {
        case 1:
            tcg_gen_ori_i32(cpu_fcw, cpu_fcw, ctx->op0 & 0xf0);
            break;
        case 3:
            tcg_gen_andi_i32(cpu_fcw, cpu_fcw, ~(ctx->op0 & 0xf0));
            break;
        case 5:
            tcg_gen_xori_i32(cpu_fcw, cpu_fcw, (ctx->op0 & 0xf0) ^ F_H);
            break;
        case 7:
            break;
        default:
            gen_unary(ctx, n3, SZ_W, &o);
            break;
        }
        break;
    case 0x0e:
    case 0x0f: /* extended instructions */
        gen_ext_insn(ctx);
        break;
    case 0x11: /* PUSHL @rd,rrs */
    case 0x13: /* PUSH @rd,rs */
        size = op6 == 0x11 ? SZ_L : SZ_W;
        gen_push(ctx, size, n2, load_reg(size, n3));
        break;
    case 0x15: /* POPL rrd,@rs */
    case 0x17: /* POP rd,@rs */
        size = op6 == 0x15 ? SZ_L : SZ_W;
        store_reg(size, n3, gen_pop(ctx, size, n2));
        break;
    case 0x1c: /* TESTL rrd */
        gen_helper_testl(tcg_env, load_rl(n2));
        break;
    case 0x1e: /* RET cc */
        {
            TCGLabel *skip = NULL;

            if (n3 == 0) {
                break;
            }
            if (n3 != 8) {
                skip = gen_new_label();
                tcg_gen_brcondi_i32(TCG_COND_EQ, gen_cond(n3), 0, skip);
            }
            t = tcg_temp_new_i32();
            if (ctx->seg) {
                v = gen_pop(ctx, SZ_L, sp_reg(ctx));
                tcg_gen_shri_i32(t, v, 31);
                gen_set_pc_b15(t);
                tcg_gen_andi_i32(t, v, 0x7f000000);
                tcg_gen_shri_i32(t, t, 8);
                tcg_gen_deposit_i32(t, t, v, 0, 16);
                tcg_gen_ori_i32(t, t, ctx->pc & Z8000_SYS_TAG);
            } else {
                v = gen_pop(ctx, SZ_W, sp_reg(ctx));
                tcg_gen_ori_i32(t, v, ctx->pc & 0xffff0000);
            }
            gen_jump_dyn(ctx, t);
            if (skip) {
                gen_set_label(skip);
                gen_goto_tb(ctx, 1, ctx->pc);
            }
        }
        break;
    case 0x22 ... 0x27: /* RES/SET/BIT r,#b */
        gen_bitop(ctx, (op6 - 0x22) >> 1, size, &o,
                  tcg_constant_i32(1 << n3));
        break;
    case 0x28 ... 0x2b: /* INC/DEC r,#n */
        {
            static gen_op2_fn * const incdec[4] = {
                gen_helper_incb, gen_helper_incw,
                gen_helper_decb, gen_helper_decw,
            };
            v = load_reg(size, n2);
            r = tcg_temp_new_i32();
            incdec[op6 - 0x28](r, tcg_env, v, tcg_constant_i32(n3 + 1));
            store_reg(size, n2, r);
        }
        break;
    case 0x2c: /* EXB rbd,rbs */
    case 0x2d: /* EX rd,rs */
        v = load_reg(size, n2);
        t = load_reg(size, n3);
        store_reg(size, n2, t);
        store_reg(size, n3, v);
        break;
    case 0x2e: /* TCCB cc,rbd */
    case 0x2f: /* TCC cc,rd */
        v = gen_cond(n3);
        if (size == SZ_W || (n2 & 8)) {
            int r16 = size == SZ_W ? n2 : (n2 & 7);
            tcg_gen_or_i32(cpu_r[r16], cpu_r[r16], v);
        } else {
            tcg_gen_shli_i32(v, v, 8);
            tcg_gen_or_i32(cpu_r[n2], cpu_r[n2], v);
        }
        break;
    case 0x30: /* DAB */
        v = load_rb(n2);
        r = tcg_temp_new_i32();
        gen_helper_dab(r, tcg_env, v);
        store_rb(n2, r);
        break;
    case 0x31: /* EXTSB/EXTS/EXTSL */
        if (n3 == 0) {
            tcg_gen_ext8s_i32(cpu_r[n2], cpu_r[n2]);
            tcg_gen_ext16u_i32(cpu_r[n2], cpu_r[n2]);
        } else if (n3 == 7) {
            v = load_rl((n2 & 12) + 2);
            tcg_gen_sari_i32(v, v, 31);
            store_rl(n2 & 12, v);
        } else {
            v = tcg_temp_new_i32();
            tcg_gen_ext16s_i32(v, cpu_r[(n2 & 14) | 1]);
            store_rl(n2, v);
        }
        break;
    case 0x32:
    case 0x33:
        gen_shift(ctx, size, n2, n3);
        break;
    case 0x34 ... 0x37: /* ADCB/ADC/SBCB/SBC */
        v = load_reg(size, n2);
        t = load_reg(size, n3);
        r = tcg_temp_new_i32();
        adc[op6 - 0x34](r, tcg_env, t, v);
        store_reg(size, n3, r);
        break;
    case 0x38: /* translate */
        gen_block(ctx, gen_helper_blk_tr);
        break;
    case 0x3a:
    case 0x3b: /* block compare and move */
        gen_block(ctx, (n3 & 7) == 1 ? gen_helper_blk_ld : gen_helper_blk_cp);
        break;
    case 0x3c: /* RRDB */
        gen_helper_rrdb(tcg_env, tcg_constant_i32(n2), tcg_constant_i32(n3));
        break;
    case 0x3d: /* LDK */
        tcg_gen_movi_i32(cpu_r[n2], n3);
        break;
    case 0x3e: /* RLDB */
        gen_helper_rldb(tcg_env, tcg_constant_i32(n2), tcg_constant_i32(n3));
        break;
    default:
        /* reserved encodings execute as no-ops */
        break;
    }
}

/* Privileged, control and I/O instructions with first byte 0x38-0x3F. */
static void gen_io_group(DisasContext *ctx, int op6, int n2, int n3)
{
    bool word = op6 & 1;
    uint32_t flags = word ? 1 : 0;
    TCGv_i32 v;

    switch (op6) {
    case 0x39: /* LDPS @rs */
        if (check_priv(ctx)) {
            gen_sync_pc(ctx);
            gen_helper_ldps(tcg_env, ea_reg(ctx, n2), tcg_constant_i32(1));
            gen_exit(ctx);
        }
        break;
    case 0x3a:
    case 0x3b:
        if (!check_priv(ctx)) {
            break;
        }
        if ((n3 & 4) && n3 < 8) {
            uint32_t port = fetch(ctx);

            flags |= (n3 & 1) ? 2 : 0;
            if (n3 & 2) {
                gen_helper_out(tcg_env, tcg_constant_i32(port),
                               load_reg(word, n2), tcg_constant_i32(flags));
            } else {
                v = tcg_temp_new_i32();
                gen_helper_in(v, tcg_env, tcg_constant_i32(port),
                              tcg_constant_i32(flags));
                store_reg(word, n2, v);
            }
        } else {
            gen_block(ctx, gen_helper_blk_io);
        }
        break;
    case 0x3c:
    case 0x3d: /* IN rd,@rs */
        if (check_priv(ctx)) {
            v = tcg_temp_new_i32();
            gen_helper_in(v, tcg_env, cpu_r[n2], tcg_constant_i32(flags));
            store_reg(word, n3, v);
        }
        break;
    case 0x3e:
    case 0x3f: /* OUT @rd,rs */
        if (check_priv(ctx)) {
            gen_helper_out(tcg_env, cpu_r[n2], load_reg(word, n3),
                           tcg_constant_i32(flags));
        }
        break;
    default:
        break;
    }
}

/* System instructions with first byte 0x78-0x7F. */
static void gen_system(DisasContext *ctx, int op6, int n2, int n3)
{
    uint16_t op = ctx->op0;
    TCGv_i32 v;

    switch (op6) {
    case 0x39: /* LDPS addr / addr(rs) */
        if (check_priv(ctx)) {
            uint32_t addr = fetch_addr(ctx);

            gen_sync_pc(ctx);
            gen_helper_ldps(tcg_env,
                            n2 ? ea_x(ctx, addr, n2) : ea_da(ctx, addr),
                            tcg_constant_i32(n2 ? 0 : 1));
            gen_exit(ctx);
        }
        break;
    case 0x3a: /* HALT */
        if (check_priv(ctx)) {
            gen_sync_pc(ctx);
            gen_helper_halt(tcg_env);
            ctx->base.is_jmp = DISAS_NORETURN;
        }
        break;
    case 0x3b:
        if (!check_priv(ctx)) {
            break;
        }
        if (op == 0x7b00) { /* IRET */
            gen_sync_pc(ctx);
            gen_helper_iret(tcg_env);
            gen_exit(ctx);
        } else if (n3 == 0xd) { /* MREQ: no multi-micro request pending */
            tcg_gen_andi_i32(cpu_fcw, cpu_fcw, ~F_S);
            tcg_gen_ori_i32(cpu_fcw, cpu_fcw, F_Z);
        }
        /* MSET, MRES and MBIT have no effect without a multi-micro bus */
        break;
    case 0x3c: /* DI / EI */
        if (check_priv(ctx)) {
            v = tcg_temp_new_i32();
            if (op & 4) {
                tcg_gen_ori_i32(v, cpu_fcw, ((~op & 3) << 11) & 0x1800);
            } else {
                tcg_gen_andi_i32(v, cpu_fcw, ((op & 3) << 11) | 0xe7ff);
            }
            gen_helper_change_fcw(tcg_env, v);
            gen_sync_pc(ctx);
            gen_exit(ctx);
        }
        break;
    case 0x3d: /* LDCTL */
        if (check_priv(ctx)) {
            if (n3 & 8) {
                gen_helper_ldctl_wr(tcg_env, tcg_constant_i32(n3 & 7),
                                    cpu_r[n2]);
                if ((n3 & 7) == 2) {
                    gen_sync_pc(ctx);
                    gen_exit(ctx);
                }
            } else {
                v = tcg_temp_new_i32();
                gen_helper_ldctl_rd(v, tcg_env, tcg_constant_i32(n3 & 7));
                if ((n3 & 7) >= 2) {
                    tcg_gen_mov_i32(cpu_r[n2], v);
                }
            }
        }
        break;
    case 0x3f: /* SC */
        gen_trap(ctx, EXCP_Z8000_SC, ctx->pc);
        break;
    default:
        break;
    }
}

static void translate_insn(DisasContext *ctx)
{
    uint16_t op = fetch(ctx);
    int mode = op >> 14;
    int op6 = (op >> 8) & 0x3f;
    int n1 = (op >> 8) & 15;
    int n2 = (op >> 4) & 15;
    int n3 = op & 15;
    int size = op6 & 1;
    Operand o;
    TCGv_i32 v, t, a;
    uint32_t addr;
    uint16_t w;

    ctx->op0 = op;

    if (!(z8000_valid_op[op >> 3] & (1 << (op & 7)))) {
        /* not an instruction: the reference core executes a no-op */
        return;
    }

    if (mode == 3) {
        switch (op >> 12) {
        case 0xc: /* LDB rbd,#imm8 */
            store_rb(n1, tcg_constant_i32(op & 0xff));
            break;
        case 0xd: /* CALR */
            {
                int d = op & 0xfff;

                d = (d & 2048) ? 4096 - 2 * (d & 2047) : -2 * (d & 2047);
                gen_push_pc(ctx);
                gen_goto_tb(ctx, 0, jump_target(ctx, addr_add(ctx->pc, d)));
            }
            break;
        case 0xe: /* JR cc */
            gen_branch_cc(ctx, n1,
                          jump_target(ctx, addr_add(ctx->pc,
                                                    (int8_t)op * 2)),
                          ctx->pc_b15);
            break;
        default: /* DJNZ / DBJNZ */
            {
                TCGLabel *done = gen_new_label();
                uint32_t dest = jump_target(ctx, addr_add(ctx->pc,
                                                          -2 * (op & 0x7f)));

                if (op & 0x80) {
                    tcg_gen_subi_i32(cpu_r[n1], cpu_r[n1], 1);
                    tcg_gen_ext16u_i32(cpu_r[n1], cpu_r[n1]);
                    tcg_gen_brcondi_i32(TCG_COND_EQ, cpu_r[n1], 0, done);
                } else {
                    v = load_rb(n1);
                    tcg_gen_subi_i32(v, v, 1);
                    tcg_gen_andi_i32(v, v, 0xff);
                    store_rb(n1, v);
                    tcg_gen_brcondi_i32(TCG_COND_EQ, v, 0, done);
                }
                gen_goto_tb(ctx, 0, dest);
                gen_set_label(done);
                gen_goto_tb(ctx, 1, ctx->pc);
            }
            break;
        }
        return;
    }

    if (gen_dyadic(ctx, mode, op6, n2, n3)) {
        return;
    }
    if (mode == 2) {
        gen_group2(ctx, op6, n2, n3);
        return;
    }
    if (op6 >= 0x38) {
        if (mode == 0) {
            gen_io_group(ctx, op6, n2, n3);
        } else {
            gen_system(ctx, op6, n2, n3);
        }
        return;
    }

    /* Memory-operand groups: mode 0 (IR/IM) and mode 1 (DA/X). */
    switch (op6) {
    case 0x0c:
    case 0x0d:
        if (op6 == 0x0d && n3 == 9) { /* PUSH @rd,#imm16 */
            gen_push(ctx, SZ_W, n2, fetch_imm(ctx, SZ_W));
            break;
        }
        decode_operand(ctx, mode, n2, &o);
        gen_unary(ctx, n3, size, &o);
        break;
    case 0x0e:
    case 0x0f:
        /* 0E, 0F, 4E and 4F are extended instructions */
        gen_ext_insn(ctx);
        break;
    case 0x11: /* PUSHL @rd,src */
    case 0x13: /* PUSH @rd,src */
        size = op6 == 0x11 ? SZ_L : SZ_W;
        if (mode == 0) {
            a = ea_reg(ctx, n3);
        } else {
            addr = fetch_addr(ctx);
            a = n3 ? ea_x(ctx, addr, n3) : ea_da(ctx, addr);
        }
        v = tcg_temp_new_i32();
        gen_ld(ctx, size, v, a, MMU_DATA_IDX);
        gen_push(ctx, size, n2, v);
        break;
    case 0x15: /* POPL dst,@rs */
    case 0x17: /* POP dst,@rs */
        size = op6 == 0x15 ? SZ_L : SZ_W;
        if (mode == 0) {
            v = gen_pop(ctx, size, n2);
            a = ea_reg(ctx, n3);
        } else {
            addr = fetch_addr(ctx);
            a = n3 ? ea_x(ctx, addr, n3) : ea_da(ctx, addr);
            v = gen_pop(ctx, size, n2);
        }
        gen_st(ctx, size, v, a, MMU_DATA_IDX);
        break;
    case 0x1c: /* TESTL, LDM */
        if (n3 == 8) {
            decode_operand(ctx, mode, n2, &o);
            gen_helper_testl(tcg_env, operand_load(ctx, &o, SZ_L));
        } else {
            w = fetch(ctx);
            decode_operand(ctx, mode, n2, &o);
            gen_sync_pc(ctx);
            gen_helper_ldm(tcg_env, o.addr, tcg_constant_i32((w >> 8) & 15),
                           tcg_constant_i32(w & 15),
                           tcg_constant_i32(n3 == 9));
        }
        break;
    case 0x1d: /* LDL dst,rrs */
        decode_operand(ctx, mode, n2, &o);
        operand_store(ctx, &o, SZ_L, load_rl(n3));
        break;
    case 0x1e: /* JP cc,dst */
        if (mode == 1 && n2 == 0) {
            addr = fetch_addr(ctx);
            gen_branch_cc(ctx, n3, jump_target_addr(ctx, addr),
                          jump_b15_addr(ctx));
        } else {
            TCGLabel *skip = NULL;

            addr = mode == 1 ? fetch_addr(ctx) : 0;
            if (n3 == 0) {
                break;
            }
            if (n3 != 8) {
                skip = gen_new_label();
                tcg_gen_brcondi_i32(TCG_COND_EQ, gen_cond(n3), 0, skip);
            }
            a = mode == 1 ? jump_x(ctx, addr, n2) : jump_reg(ctx, n2);
            gen_jump_dyn(ctx, a);
            if (skip) {
                gen_set_label(skip);
                gen_goto_tb(ctx, 1, ctx->pc);
            }
        }
        break;
    case 0x1f: /* CALL dst */
        if (mode == 1) {
            addr = fetch_addr(ctx);
            gen_push_pc(ctx);
            if (n2 == 0) {
                gen_jump_const(ctx, 0, jump_target_addr(ctx, addr),
                               jump_b15_addr(ctx));
            } else {
                gen_jump_dyn(ctx, jump_x(ctx, addr, n2));
            }
        } else {
            gen_push_pc(ctx);
            gen_jump_dyn(ctx, jump_reg(ctx, n2));
        }
        break;
    case 0x22 ... 0x27: /* RES/SET/BIT */
        if (mode == 0 && n2 == 0) {
            /* bit number in a register, operand in a register */
            w = fetch(ctx);
            t = tcg_temp_new_i32();
            tcg_gen_andi_i32(t, cpu_r[n3], size == SZ_B ? 7 : 15);
            v = tcg_temp_new_i32();
            tcg_gen_shl_i32(v, tcg_constant_i32(1), t);
            o.kind = K_R;
            o.reg = (w >> 8) & 15;
            gen_bitop(ctx, (op6 - 0x22) >> 1, size, &o, v);
        } else {
            decode_operand(ctx, mode, n2, &o);
            gen_bitop(ctx, (op6 - 0x22) >> 1, size, &o,
                      tcg_constant_i32(1 << n3));
        }
        break;
    case 0x28 ... 0x2b: /* INC/DEC dst,#n */
        {
            static gen_op2_fn * const incdec[4] = {
                gen_helper_incb, gen_helper_incw,
                gen_helper_decb, gen_helper_decw,
            };
            decode_operand(ctx, mode, n2, &o);
            v = operand_load(ctx, &o, size);
            t = tcg_temp_new_i32();
            incdec[op6 - 0x28](t, tcg_env, v, tcg_constant_i32(n3 + 1));
            operand_store(ctx, &o, size, t);
        }
        break;
    case 0x2c:
    case 0x2d: /* EX r,src */
        decode_operand(ctx, mode, n2, &o);
        v = operand_load(ctx, &o, size);
        operand_store(ctx, &o, size, load_reg(size, n3));
        store_reg(size, n3, v);
        break;
    case 0x2e:
    case 0x2f: /* LD dst,r */
        decode_operand(ctx, mode, n2, &o);
        operand_store(ctx, &o, size, load_reg(size, n3));
        break;
    case 0x30 ... 0x37:
        if (mode == 0 && n2 == 0) {
            /* PC-relative forms */
            if (op6 == 0x36) {
                if (op == 0x3600) { /* breakpoint trap */
                    gen_trap(ctx, EXCP_Z8000_PRIV, ctx->insn_pc + 2);
                }
                break;
            }
            w = fetch(ctx);
            addr = addr_add(ctx->pc, (int16_t)w);
            a = tcg_constant_i32((addr & 0x7fffff) |
                                 (ctx->pc & Z8000_SYS_TAG));
            switch (op6) {
            case 0x30:
            case 0x31:
                v = tcg_temp_new_i32();
                gen_ld(ctx, size, v, a, MMU_CODE_IDX);
                store_reg(size, n3, v);
                break;
            case 0x32:
            case 0x33:
                gen_st(ctx, size, load_reg(size, n3), a, MMU_CODE_IDX);
                break;
            case 0x34: /* LDAR */
                if (ctx->seg) {
                    tcg_gen_movi_i32(cpu_r[n3], ((addr >> 8) & 0x7f00) |
                                     (ctx->pc_b15 ? 0x8000 : 0));
                    tcg_gen_movi_i32(cpu_r[n3 | 1], addr & 0xffff);
                } else {
                    tcg_gen_movi_i32(cpu_r[n3], addr & 0xffff);
                }
                break;
            case 0x35:
                v = tcg_temp_new_i32();
                gen_ld(ctx, SZ_L, v, a, MMU_CODE_IDX);
                store_rl(n3, v);
                break;
            case 0x37:
                gen_st(ctx, SZ_L, load_rl(n3), a, MMU_CODE_IDX);
                break;
            }
            break;
        }
        if (mode == 1 && op6 == 0x36) { /* LDA prd,addr / addr(rs) */
            addr = fetch_addr_raw(ctx);
            t = n2 ? load_rw(n2) : NULL;
            if (ctx->seg) {
                tcg_gen_movi_i32(cpu_r[n3 & 14], addr >> 16);
                tcg_gen_movi_i32(cpu_r[(n3 & 14) | 1], addr & 0xffff);
            } else {
                tcg_gen_movi_i32(cpu_r[n3], addr & 0xffff);
            }
            if (n2) {
                int r = ctx->seg ? (n3 | 1) : n3;

                tcg_gen_add_i32(cpu_r[r], cpu_r[r], t);
                tcg_gen_ext16u_i32(cpu_r[r], cpu_r[r]);
            }
            break;
        }
        if (op6 == 0x36) {
            break;
        }
        /* based (mode 0) and base-indexed (mode 1) forms */
        w = fetch(ctx);
        if (mode == 0) {
            t = tcg_constant_i32(w);
        } else {
            t = load_rw((w >> 8) & 15);
        }
        if (op6 == 0x34) { /* LDA */
            gen_lda_based(ctx, n3, n2, t);
            break;
        }
        a = ea_add(ea_reg(ctx, n2), t);
        if (op6 == 0x35 || op6 == 0x37) {
            size = SZ_L;
        }
        if (op6 == 0x32 || op6 == 0x33 || op6 == 0x37) {
            gen_st(ctx, size, load_reg(size, n3), a, MMU_DATA_IDX);
        } else {
            v = tcg_temp_new_i32();
            gen_ld(ctx, size, v, a, MMU_DATA_IDX);
            store_reg(size, n3, v);
        }
        break;
    default:
        break;
    }
}

/* ---- translator hooks ---- */

static void z8000_tr_init_disas_context(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    uint32_t flags = ctx->base.tb->flags;

    ctx->env = cpu_env(cs);
    ctx->pc = ctx->base.pc_first;
    ctx->pcseg = ctx->pc & 0x7f0000;
    ctx->seg = flags & TB_FLAG_SEG;
    ctx->sys = flags & TB_FLAG_SYS;
    ctx->epu = flags & TB_FLAG_EPU;
    ctx->pc_b15 = flags & TB_FLAG_PCB15;
    ctx->data_tag = (flags & TB_FLAG_SPLIT) ? Z8000_DATA_TAG :
                    (flags & TB_FLAG_SYSSPACE) ? Z8000_SYS_TAG : 0;
}

static void z8000_tr_tb_start(DisasContextBase *db, CPUState *cs)
{
}

static void z8000_tr_insn_start(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    tcg_gen_insn_start(ctx->pc, 0, 0);
}

static void z8000_tr_translate_insn(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    ctx->insn_pc = ctx->pc;
    translate_insn(ctx);
    ctx->base.pc_next = ctx->pc;

    if (ctx->base.is_jmp == DISAS_NEXT) {
        uint32_t page_first = ctx->base.pc_first & TARGET_PAGE_MASK;

        if (ctx->pc - page_first >= TARGET_PAGE_SIZE - 10) {
            ctx->base.is_jmp = DISAS_TOO_MANY;
        }
    }
}

static void z8000_tr_tb_stop(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    switch (ctx->base.is_jmp) {
    case DISAS_NORETURN:
        break;
    case DISAS_NEXT:
    case DISAS_TOO_MANY:
        gen_goto_tb(ctx, 0, ctx->pc);
        break;
    case DISAS_EXIT:
        tcg_gen_exit_tb(NULL, 0);
        break;
    default:
        g_assert_not_reached();
    }
}

static const TranslatorOps z8000_tr_ops = {
    .init_disas_context = z8000_tr_init_disas_context,
    .tb_start           = z8000_tr_tb_start,
    .insn_start         = z8000_tr_insn_start,
    .translate_insn     = z8000_tr_translate_insn,
    .tb_stop            = z8000_tr_tb_stop,
};

void z8000_cpu_translate_code(CPUState *cs, TranslationBlock *tb,
                              int *max_insns, vaddr pc, void *host_pc)
{
    DisasContext dc = { };

    translator_loop(cs, tb, max_insns, pc, host_pc, &z8000_tr_ops, &dc.base,
                    TCG_TYPE_VA);
}
