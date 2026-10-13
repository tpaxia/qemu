/*
 * ZEUS user-mode emulation: floating point
 *
 * ZEUS programs use the Z8000 extended (floating-point) instructions
 * directly.  On a System 8000 without the floating-point unit these trap,
 * and the kernel executes them with Zilog's software emulator.  The same
 * is done here, with the same code: the emulator is taken, already linked,
 * from the kernel image in the ZEUS root (/zeus), placed in a system space
 * of its own, and run as guest code each time the program traps.
 *
 * What the kernel provides around the emulator is provided here instead:
 *
 *  - the saved-state frame and the per-process floating-point work area;
 *  - the three routines the emulator uses to reach the program's memory
 *    (gettext, getmem, putmem), replaced by traps into this file;
 *  - the mapping of its result to signals.
 *
 * No floating-point arithmetic is done by host code.
 *
 * Only non-segmented programs are handled.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/bswap.h"
#include "qemu.h"

/* Layout of the system space (segment << 16 | offset, plus the tag) */
#define KSEG_STACK      0x3e            /* kernel stack and per-process data */
#define K_FRAME         0xe000          /* saved user state, in KSEG_STACK */
#define K_STACK_TOP     0xd000
#define K_RETURN        0xdf00          /* where the emulator returns to */
#define K_WORKSPACE     0xf942          /* floating-point work area */

/* Traps planted in the system space */
#define FPE_SC_GETTEXT  0xf0
#define FPE_SC_GETMEM   0xf1
#define FPE_SC_PUTMEM   0xf2
#define FPE_SC_DONE     0xf3

/* Offsets in the saved-state frame */
#define FR_INSN  0x20
#define FR_FCW   0x22
#define FR_PCSEG 0x24
#define FR_PCOFF 0x26

static bool fpe_loaded;
static uint32_t fpe_entry;

typedef struct FpeSaved {
    uint32_t pc, fcw, data_tag;
} FpeSaved;

static FpeSaved saved;

static void *sys_ptr(uint32_t seg, uint32_t off)
{
    return g2h_untagged(Z8000_SYS_TAG | (seg << 16) | (off & 0xffff));
}

/* Host pointer for a segmented address held in a register pair. */
static void *sys_ptr_rr(CPUZ8000State *env, int reg)
{
    return sys_ptr((env->regs[reg] >> 8) & 0x7f, env->regs[reg + 1]);
}

/*
 * Load the kernel image and prepare the system space.  Returns false, with
 * a message, when the emulator cannot be set up.
 */
static bool fpe_load(void)
{
    static const char * const want[] = { "fpepu", "gettext", "getmem",
                                         "putmem" };
    g_autofree char *file = NULL;
    g_autofree gchar *data = NULL;
    uint32_t addr[4] = { 0 };
    uint32_t magic, imsize, segt, nsyms, off;
    const uint8_t *d, *tab;
    gsize len;

    if (!zeus_sysroot) {
        error_report("floating point needs the ZEUS kernel image; give the "
                     "ZEUS root with -L");
        return false;
    }
    file = g_strconcat(zeus_sysroot, "/zeus", NULL);
    if (!g_file_get_contents(file, &data, &len, NULL)) {
        error_report("floating point needs the ZEUS kernel image %s", file);
        return false;
    }
    d = (const uint8_t *)data;
    magic = len >= 24 ? lduw_be_p(d) : 0;
    imsize = ldl_be_p(d + 2);
    segt = lduw_be_p(d + 10);
    nsyms = lduw_be_p(d + 12);
    if ((magic & 0xff00) != 0xe600 || len < 24 + segt + imsize + nsyms) {
        error_report("%s is not a segmented ZEUS kernel image", file);
        return false;
    }

    /* each segment's code and data follow one another in the image */
    off = 24 + segt;
    for (uint32_t i = 0; i < segt; i += 16) {
        const uint8_t *e = d + 24 + i;
        uint32_t seg = e[0] & 0x7f;
        uint32_t size = lduw_be_p(e + 4) + lduw_be_p(e + 6);

        zeus_map_space(Z8000_SYS_TAG | (seg << 16));
        memcpy(sys_ptr(seg, 0), d + off, size);
        off += size;
    }
    zeus_map_space(Z8000_SYS_TAG | (KSEG_STACK << 16));

    /* symbol table: long value, type, pad, eight-character name */
    tab = d + 24 + segt + imsize;
    for (uint32_t i = 0; i + 14 <= nsyms; i += 14) {
        char name[9] = { 0 };

        memcpy(name, tab + i + 6, 8);
        for (int k = 0; k < ARRAY_SIZE(want); k++) {
            if (tab[i + 4] == 98 && !strcmp(name, want[k])) {
                addr[k] = ldl_be_p(tab + i);
            }
        }
    }
    for (int k = 0; k < ARRAY_SIZE(want); k++) {
        if (!addr[k] || (addr[k] >> 24) != 0) {
            error_report("%s: no usable '%s'; not a kernel with the software "
                         "floating-point emulator", file, want[k]);
            return false;
        }
    }
    fpe_entry = addr[0] & 0xffff;

    /* the memory routines become "trap, return" */
    for (int k = 1; k < 4; k++) {
        uint8_t *p = sys_ptr(0, addr[k]);

        stw_be_p(p, 0x7f00 | (FPE_SC_GETTEXT + k - 1));
        stw_be_p(p + 2, 0x9e08);
    }
    stw_be_p(sys_ptr(KSEG_STACK, K_RETURN), 0x7f00 | FPE_SC_DONE);
    fpe_loaded = true;
    return true;
}

/*
 * The program executed an extended instruction: its PC is just past the
 * first word.  Switch the CPU to the emulator.
 */
bool zeus_fpe_enter(CPUZ8000State *env)
{
    TaskState *ts = get_task_state(env_cpu(env));
    uint8_t *frame;

    if (!fpe_loaded && !fpe_load()) {
        return false;
    }

    frame = sys_ptr(KSEG_STACK, K_FRAME);
    for (int i = 0; i < 16; i++) {
        stw_be_p(frame + 2 * i, env->regs[i]);
    }
    stw_be_p(frame + FR_INSN, env->op0);
    /* as the kernel's trap handler leaves the saved FCW */
    stw_be_p(frame + FR_FCW, (env->fcw & 0xf8fc) | 0x0100);
    stw_be_p(frame + FR_PCSEG, 0x3f00);
    stw_be_p(frame + FR_PCOFF, env->pc & 0xffff);

    saved.pc = env->pc;
    saved.fcw = env->fcw;
    saved.data_tag = env->data_tag;
    ts->in_fpe = true;

    /* fpepu(frame, workspace), called from K_RETURN, on the kernel stack */
    memset(env->regs, 0, sizeof(env->regs));
    env->regs[6] = KSEG_STACK << 8;
    env->regs[7] = K_FRAME;
    env->regs[4] = KSEG_STACK << 8;
    env->regs[5] = K_WORKSPACE;
    env->regs[14] = KSEG_STACK << 8;
    env->regs[15] = K_STACK_TOP - 4;
    stl_be_p(sys_ptr(KSEG_STACK, K_STACK_TOP - 4),
             0x80000000 | (KSEG_STACK << 24) | K_RETURN);
    env->fcw = F_SEG | F_S_N;
    env->data_tag = Z8000_SYS_TAG;
    env->pc = Z8000_SYS_TAG | fpe_entry;
    return true;
}

/* The emulator returned: R2 holds its verdict. */
static void fpe_done(CPUZ8000State *env)
{
    TaskState *ts = get_task_state(env_cpu(env));
    const uint8_t *frame = sys_ptr(KSEG_STACK, K_FRAME);
    uint32_t verdict = env->regs[2];

    for (int i = 0; i < 16; i++) {
        env->regs[i] = lduw_be_p(frame + 2 * i);
    }
    env->fcw = (saved.fcw & 0xff00) | (lduw_be_p(frame + FR_FCW) & 0x00fc);
    env->pc = (saved.pc & 0xffff0000) | lduw_be_p(frame + FR_PCOFF);
    env->data_tag = saved.data_tag;
    ts->in_fpe = false;

    /* the kernel sends SIGSEGV for the low byte, SIGFPE for the high one */
    if (verdict & 0x00ff) {
        fflush(stdout);
        fprintf(stderr, "qemu-" TARGET_NAME ": memory fault in a "
                "floating-point instruction, pc %04x\n", env->pc & 0xffff);
        exit(128 + SIGSEGV);
    }
    if (verdict & 0xff00) {
        fflush(stdout);
        fprintf(stderr, "qemu-" TARGET_NAME ": floating-point exception, "
                "pc %04x\n", env->pc & 0xffff);
        exit(128 + SIGFPE);
    }
}

/* Program memory, in the space the program was using when it trapped. */
static void *user_ptr(uint32_t addr, uint32_t len, uint32_t tag, bool write)
{
    addr &= 0xffff;
    if (len > ZEUS_SPACE_SIZE - addr) {
        return NULL;
    }
    if (write && len && !page_check_range(tag | addr, len, PAGE_WRITE)) {
        return NULL;
    }
    return g2h_untagged(tag | addr);
}

/*
 * A trap from the system space.  Each memory routine returns its status in
 * R2: zero, or 0xff in the low byte when the program's memory is bad.
 */
void zeus_fpe_call(CPUZ8000State *env, int num)
{
    uint32_t count = env->regs[3];
    void *u, *k;

    switch (num) {
    case FPE_SC_GETTEXT:
        /* fetch one instruction word at (R6:)R7 into R3 */
        u = user_ptr(env->regs[7], 2, 0, false);
        if (u) {
            env->regs[3] = lduw_be_p(u);
            env->regs[2] = 0;
        } else {
            env->regs[2] = (env->regs[2] & 0xff00) | 0xff;
        }
        break;
    case FPE_SC_GETMEM:
        /* copy R3 bytes from the program's data at R7 to RR4 */
        u = user_ptr(env->regs[7], count, saved.data_tag, false);
        k = sys_ptr_rr(env, 4);
        if (u) {
            memcpy(k, u, count);
            env->regs[2] = 0;
        } else {
            env->regs[2] = (env->regs[2] & 0xff00) | 0xff;
        }
        break;
    case FPE_SC_PUTMEM:
        /* copy R3 bytes from RR6 to the program's data at R5 */
        u = user_ptr(env->regs[5], count, saved.data_tag, true);
        k = sys_ptr_rr(env, 6);
        if (u) {
            memcpy(u, k, count);
            env->regs[2] = 0;
        } else {
            env->regs[2] = (env->regs[2] & 0xff00) | 0xff;
        }
        break;
    case FPE_SC_DONE:
        fpe_done(env);
        break;
    default:
        error_report("unexpected trap %#x in the floating-point emulator",
                     num);
        exit(EXIT_FAILURE);
    }
}
