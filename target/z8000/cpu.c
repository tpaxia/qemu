/*
 * Zilog Z8000 CPU model
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/qemu-print.h"
#include "exec/translation-block.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "cpu.h"
#include "tcg/debug-assert.h"
#include "accel/tcg/cpu-ops.h"

static void z8000_cpu_set_pc(CPUState *cs, vaddr value)
{
    cpu_env(cs)->pc = value;
}

static vaddr z8000_cpu_get_pc(CPUState *cs)
{
    return cpu_env(cs)->pc;
}

static bool z8000_cpu_has_work(CPUState *cs)
{
    return cpu_test_interrupt(cs, CPU_INTERRUPT_HARD);
}

static int z8000_cpu_mmu_index(CPUState *cs, bool ifetch)
{
    return ifetch ? MMU_CODE_IDX : MMU_DATA_IDX;
}

static TCGTBCPUState z8000_get_tb_cpu_state(CPUState *cs)
{
    CPUZ8000State *env = cpu_env(cs);
    uint32_t flags = 0;

    if (z8000_segmented_mode(env)) {
        flags |= TB_FLAG_SEG;
    }
    if (env->fcw & F_S_N) {
        flags |= TB_FLAG_SYS;
    }
    if (env->fcw & F_EPU) {
        flags |= TB_FLAG_EPU;
    }
    return (TCGTBCPUState){ .pc = env->pc, .flags = flags };
}

static void z8000_cpu_synchronize_from_tb(CPUState *cs,
                                          const TranslationBlock *tb)
{
    tcg_debug_assert(!tcg_cflags_has(cs, CF_PCREL));
    cpu_env(cs)->pc = tb->pc;
}

static void z8000_restore_state_to_opc(CPUState *cs,
                                       const TranslationBlock *tb,
                                       const uint64_t *data)
{
    cpu_env(cs)->pc = data[0];
}

static uint32_t reset_ldw(uint32_t addr)
{
    uint8_t buf[2] = { 0, 0 };

    address_space_read(&address_space_memory, addr, MEMTXATTRS_UNSPECIFIED,
                       buf, 2);
    return (buf[0] << 8) | buf[1];
}

static void z8000_cpu_reset_hold(Object *obj, ResetType type)
{
    CPUState *cs = CPU(obj);
    Z8000CPUClass *zcc = Z8000_CPU_GET_CLASS(obj);
    CPUZ8000State *env = cpu_env(cs);

    if (zcc->parent_phases.hold) {
        zcc->parent_phases.hold(obj, type);
    }

    memset(env->regs, 0, sizeof(env->regs));
    env->segmented_cpu = zcc->segmented;
    env->fcw = 0;
    env->psapseg = env->psapoff = 0;
    env->refresh = 0;
    env->nspseg = env->nspoff = 0;
    env->op0 = 0;
    env->irq_vec = 0;

    /* Program status loaded from the reset vector. */
    z8000_change_fcw(env, reset_ldw(2));
    if (zcc->segmented) {
        /* bit 15 of the segment word is kept as bit 23 of the PC */
        env->pc = ((reset_ldw(4) & 0xff00) << 8) | reset_ldw(6);
    } else {
        env->pc = reset_ldw(4);
    }
}

static void z8000_cpu_realizefn(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    Z8000CPUClass *zcc = Z8000_CPU_GET_CLASS(dev);
    Error *local_err = NULL;

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }
    qemu_init_vcpu(cs);
    cpu_reset(cs);

    zcc->parent_realize(dev, errp);
}

static ObjectClass *z8000_cpu_class_by_name(const char *cpu_model)
{
    g_autofree char *name = g_strdup_printf(Z8000_CPU_TYPE_NAME("%s"),
                                            cpu_model);
    ObjectClass *oc = object_class_by_name(name);

    if (!oc || !object_class_dynamic_cast(oc, TYPE_Z8000_CPU) ||
        object_class_is_abstract(oc)) {
        return NULL;
    }
    return oc;
}

static void z8000_cpu_dump_state(CPUState *cs, FILE *f, int flags)
{
    CPUZ8000State *env = cpu_env(cs);

    qemu_fprintf(f, "PC=<<%02x>>%04x FCW=%04x [%c%c%c %c%c%c%c%c%c] "
                 "PSAP=<<%04x>>%04x NSP=<<%04x>>%04x\n",
                 (env->pc >> 16) & 0x7f, env->pc & 0xffff, env->fcw,
                 env->fcw & F_SEG ? 'G' : '-',
                 env->fcw & F_S_N ? 'S' : 'N',
                 env->fcw & F_EPU ? 'E' : '-',
                 env->fcw & F_C ? 'C' : '-',
                 env->fcw & F_Z ? 'Z' : '-',
                 env->fcw & F_S ? 'S' : '-',
                 env->fcw & F_PV ? 'V' : '-',
                 env->fcw & F_DA ? 'D' : '-',
                 env->fcw & F_H ? 'H' : '-',
                 env->psapseg, env->psapoff, env->nspseg, env->nspoff);
    for (int i = 0; i < 16; i++) {
        qemu_fprintf(f, "R%-2d=%04x%s", i, env->regs[i],
                     (i % 8) == 7 ? "\n" : " ");
    }
}

#include "hw/core/sysemu-cpu-ops.h"

static const struct SysemuCPUOps z8000_sysemu_ops = {
    .has_work = z8000_cpu_has_work,
    .get_phys_addr_debug = z8000_cpu_get_phys_addr_debug,
};

static const TCGCPUOps z8000_tcg_ops = {
    .guest_default_memory_order = 0,
    .mttcg_supported = false,
    .initialize = z8000_cpu_tcg_init,
    .translate_code = z8000_cpu_translate_code,
    .get_tb_cpu_state = z8000_get_tb_cpu_state,
    .synchronize_from_tb = z8000_cpu_synchronize_from_tb,
    .restore_state_to_opc = z8000_restore_state_to_opc,
    .mmu_index = z8000_cpu_mmu_index,
    .cpu_exec_interrupt = z8000_cpu_exec_interrupt,
    .cpu_exec_halt = z8000_cpu_has_work,
    .cpu_exec_reset = cpu_reset,
    .tlb_fill = z8000_cpu_tlb_fill,
    .do_interrupt = z8000_cpu_do_interrupt,
    .pointer_wrap = cpu_pointer_wrap_uint32,
};

static void z8000_cpu_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);
    Z8000CPUClass *zcc = Z8000_CPU_CLASS(oc);
    ResettableClass *rc = RESETTABLE_CLASS(oc);

    device_class_set_parent_realize(dc, z8000_cpu_realizefn,
                                    &zcc->parent_realize);
    resettable_class_set_parent_phases(rc, NULL, z8000_cpu_reset_hold, NULL,
                                       &zcc->parent_phases);

    cc->class_by_name = z8000_cpu_class_by_name;
    cc->dump_state = z8000_cpu_dump_state;
    cc->set_pc = z8000_cpu_set_pc;
    cc->get_pc = z8000_cpu_get_pc;
    cc->sysemu_ops = &z8000_sysemu_ops;
    cc->tcg_ops = &z8000_tcg_ops;
}

static void z8001_class_init(ObjectClass *oc, const void *data)
{
    Z8000_CPU_CLASS(oc)->segmented = true;
}

static void z8002_class_init(ObjectClass *oc, const void *data)
{
    Z8000_CPU_CLASS(oc)->segmented = false;
}

static const TypeInfo z8000_cpu_type_info[] = {
    {
        .name = TYPE_Z8000_CPU,
        .parent = TYPE_CPU,
        .instance_size = sizeof(Z8000CPU),
        .instance_align = __alignof(Z8000CPU),
        .class_size = sizeof(Z8000CPUClass),
        .class_init = z8000_cpu_class_init,
        .abstract = true,
    },
    {
        .name = Z8000_CPU_TYPE_NAME("z8001"),
        .parent = TYPE_Z8000_CPU,
        .class_init = z8001_class_init,
    },
    {
        .name = Z8000_CPU_TYPE_NAME("z8002"),
        .parent = TYPE_Z8000_CPU,
        .class_init = z8002_class_init,
    },
};

DEFINE_TYPES(z8000_cpu_type_info)
