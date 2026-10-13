/*
 * ZEUS user-mode emulation: s.out program loader
 *
 * Loads non-segmented executables (E707 merged, E711 separate instruction
 * and data spaces) and builds the initial stack the way the ZEUS kernel
 * does.  Segmented executables are not handled yet.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/bswap.h"
#include "qemu.h"

#define S_MAGIC_NONSEG       0xe707
#define S_MAGIC_NONSEG_SPLIT 0xe711
#define S_HDR_SIZE           24
#define S_SEGT_SIZE          16

static void put_word(CPUZ8000State *env, uint32_t addr, uint32_t v)
{
    stw_be_p(g2h_untagged(env->data_tag | (addr & 0xffff)), v);
}

/*
 * Initial stack, at the top of the data space:
 *
 *   sp -> argc, argv[0..argc-1], 0, envp[0..], 0, strings, 0
 *
 * The strings end two bytes below the top of the space.
 */
static int build_stack(CPUZ8000State *env, char **argv, char **envp,
                       uint32_t brk)
{
    int argc = g_strv_length(argv), envc = g_strv_length(envp);
    uint32_t nc = 0, ucp, sp, ap;

    for (int i = 0; i < argc; i++) {
        nc += strlen(argv[i]) + 1;
    }
    for (int i = 0; i < envc; i++) {
        nc += strlen(envp[i]) + 1;
    }
    nc = (nc + 1) & ~1;
    if (nc + 2 * (argc + envc) + 8 + 256 > ZEUS_SPACE_SIZE - brk) {
        return -E2BIG;
    }
    ucp = ZEUS_SPACE_SIZE - 2 - nc;
    sp = ucp - 2 * (argc + envc) - 6;

    put_word(env, sp, argc);
    ap = sp + 2;
    for (int pass = 0; pass < 2; pass++) {
        char **v = pass ? envp : argv;
        int n = pass ? envc : argc;

        for (int i = 0; i < n; i++) {
            size_t len = strlen(v[i]) + 1;

            put_word(env, ap, ucp);
            memcpy(g2h_untagged(env->data_tag | ucp), v[i], len);
            ap += 2;
            ucp += len;
        }
        put_word(env, ap, 0);
        ap += 2;
    }
    return sp;
}

int zeus_load(const char *filename, char **argv, char **envp,
              CPUZ8000State *env, struct image_info *info)
{
    g_autofree gchar *data = NULL;
    gsize len;
    uint32_t magic, imsize, bss, segt, entry, code = 0, dsize = 0;
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

    if (magic != S_MAGIC_NONSEG && magic != S_MAGIC_NONSEG_SPLIT) {
        if ((magic & 0xff00) == 0xe600) {
            error_report("%s: segmented executables are not supported yet",
                         filename);
        }
        return -ENOEXEC;
    }
    if (segt % S_SEGT_SIZE || len < S_HDR_SIZE + segt + imsize) {
        return -ENOEXEC;
    }
    for (uint32_t i = 0; i < segt; i += S_SEGT_SIZE) {
        const uint8_t *e = d + S_HDR_SIZE + i;

        code += lduw_be_p(e + 4);
        dsize += lduw_be_p(e + 6);
    }
    if (code + dsize != imsize) {
        return -ENOEXEC;
    }
    image = d + S_HDR_SIZE + segt;

    info->split_id = magic == S_MAGIC_NONSEG_SPLIT;
    info->entry = entry & 0xfffe;
    if (info->split_id) {
        if (code > ZEUS_SPACE_SIZE || dsize + bss > ZEUS_SPACE_SIZE) {
            return -ENOMEM;
        }
        env->data_tag = Z8000_DATA_TAG;
        zeus_map_space(0);
        zeus_map_space(Z8000_DATA_TAG);
        memcpy(g2h_untagged(0), image, code);
        memcpy(g2h_untagged(Z8000_DATA_TAG), image + code, dsize);
        info->brk = dsize + bss;
    } else {
        if (imsize + bss > ZEUS_SPACE_SIZE) {
            return -ENOMEM;
        }
        env->data_tag = 0;
        zeus_map_space(0);
        memcpy(g2h_untagged(0), image, imsize);
        info->brk = imsize + bss;
    }
    info->code_offset = 0;
    info->data_offset = env->data_tag;

    sp = build_stack(env, argv, envp, info->brk);
    if (sp < 0) {
        return sp;
    }

    /* Register state at program start, as the kernel leaves it. */
    memset(env->regs, 0, sizeof(env->regs));
    env->regs[15] = sp;
    env->fcw = 0;               /* normal mode, non-segmented */
    env->pc = info->entry;
    return 0;
}
