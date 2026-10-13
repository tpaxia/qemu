/*
 * ZEUS user-mode emulation: s.out program loader
 *
 * Loads non-segmented executables (E707 merged, E711 separate instruction
 * and data spaces) and segmented ones (E607, and E611 with separate
 * spaces), and builds the initial stack the way the ZEUS kernel does.
 * An overlay (E705) replaces the instructions of a running program.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/bswap.h"
#include "qemu.h"

#define S_MAGIC_OVERLAY      0xe705
#define S_MAGIC_NONSEG       0xe707
#define S_MAGIC_NONSEG_SPLIT 0xe711
#define S_MAGIC_SEG          0xe607
#define S_MAGIC_SEG_SPLIT    0xe611
#define S_HDR_SIZE           24
#define S_SEGT_SIZE          16

/* Header flag: the stack goes in segment 0x7f rather than 0x3f */
#define S_FLAG_STACK_7F      0x20

/* Segment table attributes */
#define SG_CODE              0x01
#define SG_DATA              0x02
#define SG_BSS               0x04

#define STACK_SEG_LOW        0x3f
#define STACK_SEG_HIGH       0x7f

static void put_word(uint32_t addr, uint32_t v)
{
    stw_be_p(g2h_untagged(addr), v);
}

/*
 * Initial stack, at the top of the data space or of the stack segment:
 *
 *   sp -> argc, argv[0..argc-1], 0, envp[0..], 0, strings, 0
 *
 * The strings end two bytes below the top.  A segmented program has
 * two-word pointers, and two spare bytes before the strings.
 */
static int build_stack(uint32_t base, bool segmented, uint32_t segword,
                       char **argv, char **envp, uint32_t floor)
{
    int argc = g_strv_length(argv), envc = g_strv_length(envp);
    int psize = segmented ? 4 : 2;
    uint32_t nc = 0, ucp, sp, ap, fixed = segmented ? 12 : 6;

    for (int i = 0; i < argc; i++) {
        nc += strlen(argv[i]) + 1;
    }
    for (int i = 0; i < envc; i++) {
        nc += strlen(envp[i]) + 1;
    }
    nc = (nc + 1) & ~1;
    if (nc + psize * (argc + envc) + fixed + 2 + 256 >
        ZEUS_SPACE_SIZE - floor) {
        return -E2BIG;
    }
    ucp = ZEUS_SPACE_SIZE - 2 - nc;
    sp = ucp - psize * (argc + envc) - fixed;

    put_word(base + sp, argc);
    ap = sp + 2;
    for (int pass = 0; pass < 2; pass++) {
        char **v = pass ? envp : argv;
        int n = pass ? envc : argc;

        for (int i = 0; i < n; i++) {
            size_t len = strlen(v[i]) + 1;

            if (segmented) {
                put_word(base + ap, segword);
                ap += 2;
            }
            put_word(base + ap, ucp);
            memcpy(g2h_untagged(base + ucp), v[i], len);
            ap += 2;
            ucp += len;
        }
        for (int i = 0; i < psize; i += 2) {
            put_word(base + ap, 0);
            ap += 2;
        }
    }
    return sp;
}

/*
 * A segmented image: every table entry names a segment, holding its
 * instructions, then its initialised data, then its bss.  With separate
 * spaces an entry with instructions holds nothing else.
 */
static int load_segmented(const uint8_t *d, uint32_t segt, uint32_t imsize,
                          struct image_info *info)
{
    const uint8_t *image = d + S_HDR_SIZE + segt;
    uint32_t off = 0;

    for (uint32_t i = 0; i < segt; i += S_SEGT_SIZE) {
        const uint8_t *e = d + S_HDR_SIZE + i;
        uint32_t no = e[0], code = lduw_be_p(e + 4), data = lduw_be_p(e + 6);
        uint32_t bss = lduw_be_p(e + 8), atr = lduw_be_p(e + 10);
        struct zeus_seg *sg = &info->segs[info->nsegs];
        uint32_t base, size = 0;

        if (info->nsegs == ZEUS_MAX_SEGS || no > STACK_SEG_HIGH ||
            off + code + data > imsize) {
            return -ENOEXEC;
        }
        for (int k = 0; k < info->nsegs; k++) {
            if (info->segs[k].no == no && (!info->split_id ||
                info->segs[k].code == !!(atr & SG_CODE))) {
                return -ENOEXEC;
            }
        }
        sg->no = no;
        base = no << 16;
        if (atr & SG_CODE) {
            if (no > STACK_SEG_LOW) {
                return -ENOEXEC;
            }
            sg->code_size = size = code;
            sg->code = info->split_id;
        }
        if (!sg->code) {
            base |= info->data_offset;
            if (atr & SG_DATA) {
                size += data;
            }
            if (atr & (SG_DATA | SG_BSS)) {
                size += bss;
            }
            if (size > ZEUS_SPACE_SIZE) {
                return -ENOEXEC;
            }
        }
        zeus_map_space(base);
        memcpy(g2h_untagged(base), image + off, code + data);
        off += code + data;
        sg->size = ROUND_UP(size, 256);
        info->nsegs++;
    }
    return 0;
}

int zeus_load(const char *filename, char **argv, char **envp,
              CPUZ8000State *env, struct image_info *info)
{
    g_autofree gchar *data = NULL;
    gsize len;
    uint32_t magic, imsize, bss, segt, entry, code = 0, dsize = 0;
    uint32_t stack_base, floor = 0;
    const uint8_t *d, *image;
    int sp;

    if (!g_file_get_contents(filename, &data, &len, NULL)) {
        return -errno;
    }
    d = (const uint8_t *)data;
    if (len < S_HDR_SIZE) {
        return -ENOEXEC;
    }
    magic = lduw_be_p(d);
    imsize = ldl_be_p(d + 2);
    bss = ldl_be_p(d + 6);
    segt = lduw_be_p(d + 10);
    entry = ldl_be_p(d + 14);

    switch (magic) {
    case S_MAGIC_NONSEG:
    case S_MAGIC_SEG:
        break;
    case S_MAGIC_NONSEG_SPLIT:
    case S_MAGIC_SEG_SPLIT:
        info->split_id = true;
        break;
    default:
        return -ENOEXEC;
    }
    info->segmented = (magic & 0xff00) == 0xe600;
    if (segt % S_SEGT_SIZE || len < S_HDR_SIZE + segt + imsize) {
        return -ENOEXEC;
    }
    env->data_tag = info->split_id ? Z8000_DATA_TAG : 0;
    info->code_offset = 0;
    info->data_offset = env->data_tag;

    if (info->segmented) {
        int r = load_segmented(d, segt, imsize, info);

        if (r < 0) {
            return r;
        }
        info->stack_seg = lduw_be_p(d + 18) & S_FLAG_STACK_7F ?
                          STACK_SEG_HIGH : STACK_SEG_LOW;
        for (int k = 0; k < info->nsegs; k++) {
            if (info->segs[k].no == info->stack_seg && !info->segs[k].code) {
                return -ENOEXEC;
            }
        }
        stack_base = info->data_offset | (info->stack_seg << 16);
        zeus_map_space(stack_base);
        info->entry = zeus_long_to_ptr(entry & ~1);
    } else {
        for (uint32_t i = 0; i < segt; i += S_SEGT_SIZE) {
            const uint8_t *e = d + S_HDR_SIZE + i;

            code += lduw_be_p(e + 4);
            dsize += lduw_be_p(e + 6);
        }
        if (code + dsize != imsize) {
            return -ENOEXEC;
        }
        image = d + S_HDR_SIZE + segt;
        info->entry = entry & 0xfffe;
        if (info->split_id) {
            if (code > ZEUS_SPACE_SIZE || dsize + bss > ZEUS_SPACE_SIZE) {
                return -ENOMEM;
            }
            zeus_map_space(0);
            zeus_map_space(Z8000_DATA_TAG);
            memcpy(g2h_untagged(0), image, code);
            memcpy(g2h_untagged(Z8000_DATA_TAG), image + code, dsize);
            info->brk = dsize + bss;
            info->text_size = code;
        } else {
            if (imsize + bss > ZEUS_SPACE_SIZE) {
                return -ENOMEM;
            }
            zeus_map_space(0);
            memcpy(g2h_untagged(0), image, imsize);
            info->brk = imsize + bss;
        }
        stack_base = info->data_offset;
        floor = info->brk;
    }

    sp = build_stack(stack_base, info->segmented, info->stack_seg << 8,
                     argv, envp, floor);
    if (sp < 0) {
        return sp;
    }

    /* Register state at program start, as the kernel leaves it. */
    memset(env->regs, 0, sizeof(env->regs));
    env->regs[15] = sp;
    if (info->segmented) {
        env->regs[14] = info->stack_seg << 8;
        env->fcw = F_SEG;       /* normal mode, segmented */
    } else {
        env->fcw = 0;           /* normal mode, non-segmented */
    }
    env->pc = info->entry;
    return 0;
}

/* The kernel compares instruction space sizes in units of 8K. */
#define OVERLAY_UNIT 0x2000

/*
 * exec of an overlay: the instructions of the running program are
 * replaced by those of the file and execution continues at its entry
 * point.  Data, stack and registers stay as they are.  The caller has
 * checked that no arguments were passed.  Returns 0 or a negative errno.
 *
 * A program with one address space has no instruction space of its own,
 * so there the kernel only accepts an overlay without instructions.
 */
int zeus_overlay(const char *filename, CPUZ8000State *env,
                 struct image_info *info)
{
    g_autofree gchar *data = NULL;
    gsize len;
    uint32_t segt, code;
    const uint8_t *d;

    if (!g_file_get_contents(filename, &data, &len, NULL)) {
        return -errno;
    }
    d = (const uint8_t *)data;
    if (len < S_HDR_SIZE + S_SEGT_SIZE || lduw_be_p(d) != S_MAGIC_OVERLAY) {
        return -ENOEXEC;
    }
    segt = lduw_be_p(d + 10);
    code = lduw_be_p(d + S_HDR_SIZE + 4);
    if (segt < S_SEGT_SIZE || len < S_HDR_SIZE + segt + code) {
        return -ENOEXEC;
    }
    if (info->segmented) {
        return -ENOEXEC;
    }
    if (!info->split_id &&
        ROUND_UP(code, OVERLAY_UNIT) != ROUND_UP(info->text_size,
                                                 OVERLAY_UNIT)) {
        return -ENOMEM;
    }
    if (info->split_id) {
        /* checking for writing discards the old translations */
        if (!page_check_range(0, ZEUS_SPACE_SIZE, PAGE_WRITE)) {
            return -ENOMEM;
        }
        memset(g2h_untagged(0), 0, ZEUS_SPACE_SIZE);
        memcpy(g2h_untagged(0), d + S_HDR_SIZE + segt, code);
        info->text_size = code;
    }
    info->entry = ldl_be_p(d + 14) & 0xfffe;
    env->pc = info->entry;
    return 0;
}
