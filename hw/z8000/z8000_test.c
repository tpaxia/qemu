/*
 * Z8000 test machine: a CPU, 8 MiB of RAM and nothing else.
 *
 * The image given with -bios is loaded at address 0.  When the guest
 * executes HALT the machine writes the CPU state, a log of port output
 * and the first "dump-size" bytes of RAM to the file named by the "dump"
 * property, then exits.  It exists to compare the translator against a
 * reference interpreter.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "qemu/error-report.h"
#include "qapi/error.h"
#include "hw/core/boards.h"
#include "system/address-spaces.h"
#include "system/memory.h"
#include "system/reset.h"
#include "target/z8000/cpu.h"
#include "qom/object.h"

#define TYPE_Z8000_TEST_MACHINE MACHINE_TYPE_NAME("z8000-test")
OBJECT_DECLARE_SIMPLE_TYPE(Z8000TestState, Z8000_TEST_MACHINE)

#define IO_LOG_MAX 65536

struct Z8000TestState {
    MachineState parent_obj;

    Z8000CPU *cpu;
    MemoryRegion ram;
    char *dump;
    uint32_t dump_size;
    uint8_t *io_log;
    uint16_t latch[3];
    uint32_t io_count;
};

/*
 * Port model, shared with the libz8000 standalone emulator so its
 * instruction suite runs unchanged:
 *   normal I/O:  0x0000 data latch (initially 0x1234), 0x0002 control latch,
 *                0x0010 reads 0xAA00, anything else reads 0xDEAD
 *   special I/O: 0x0020 data latch (initially 0x5678), anything else 0xBEEF
 */
static uint32_t test_io_word(Z8000TestState *s, uint32_t port, int special)
{
    port &= 0xfffe;
    if (!special) {
        switch (port) {
        case 0x0000: return s->latch[0];
        case 0x0002: return s->latch[1];
        case 0x0010: return 0xaa00;
        default:     return 0xdead;
        }
    }
    return port == 0x0020 ? s->latch[2] : 0xbeef;
}

static uint32_t test_io_read(void *opaque, uint32_t port, int size,
                             int special)
{
    Z8000TestState *s = opaque;
    uint32_t w = test_io_word(s, port, special);

    if (size == 2) {
        return w;
    }
    if (!special && (port & 0xfffe) == 0x0010) {
        return (port & 1) ? 0x55 : 0xaa;
    }
    if ((!special && (port & 0xfffe) > 0x0002) ||
        (special && (port & 0xfffe) != 0x0020)) {
        return w >> 8;
    }
    return (port & 1) ? (w & 0xff) : (w >> 8);
}

static void test_io_write(void *opaque, uint32_t port, uint32_t val,
                          int size, int special)
{
    Z8000TestState *s = opaque;
    int reg = -1;

    if (s->io_count < IO_LOG_MAX) {
        uint8_t *p = s->io_log + 6 * s->io_count++;

        p[0] = port >> 8;
        p[1] = port;
        p[2] = val >> 8;
        p[3] = val;
        p[4] = size;
        p[5] = special;
    }
    if (!special && (port & 0xfffe) == 0x0000) {
        reg = 0;
    } else if (!special && (port & 0xfffe) == 0x0002) {
        reg = 1;
    } else if (special && (port & 0xfffe) == 0x0020) {
        reg = 2;
    }
    if (reg < 0) {
        return;
    }
    if (size == 2) {
        s->latch[reg] = val & 0xffff;
    } else if (port & 1) {
        s->latch[reg] = (s->latch[reg] & 0xff00) | (val & 0xff);
    } else {
        s->latch[reg] = (s->latch[reg] & 0x00ff) | ((val & 0xff) << 8);
    }
}

static void put16(FILE *f, uint32_t v)
{
    fputc((v >> 8) & 0xff, f);
    fputc(v & 0xff, f);
}

static void test_halt(void *opaque)
{
    Z8000TestState *s = opaque;
    CPUZ8000State *env = &s->cpu->env;
    FILE *f;

    if (!s->dump) {
        exit(0);
    }
    f = fopen(s->dump, "wb");
    if (!f) {
        error_report("cannot write dump file '%s'", s->dump);
        exit(1);
    }
    fwrite("Z8KD", 1, 4, f);
    for (int i = 0; i < 16; i++) {
        put16(f, env->regs[i]);
    }
    /* segment number, with the PC's segment-word bit 15 in bit 15 */
    put16(f, ((env->pc >> 16) & 0x7f) | ((env->pc >> 8) & 0x8000));
    put16(f, env->pc);
    put16(f, env->fcw);
    put16(f, env->psapseg);
    put16(f, env->psapoff);
    put16(f, env->refresh);
    put16(f, env->nspseg);
    put16(f, env->nspoff);
    put16(f, s->io_count >> 16);
    put16(f, s->io_count);
    fwrite(s->io_log, 6, s->io_count, f);
    fwrite(memory_region_get_ram_ptr(&s->ram), 1, s->dump_size, f);
    fclose(f);
    exit(0);
}

static const Z8000IOOps test_io_ops = {
    .read = test_io_read,
    .write = test_io_write,
    .halt = test_halt,
};

static void test_cpu_reset(void *opaque)
{
    cpu_reset(CPU(opaque));
}

static void z8000_test_init(MachineState *machine)
{
    Z8000TestState *s = Z8000_TEST_MACHINE(machine);

    memory_region_init_ram(&s->ram, NULL, "z8000-test.ram", 8 * MiB,
                           &error_fatal);
    memory_region_add_subregion(get_system_memory(), 0, &s->ram);

    if (machine->firmware) {
        g_autofree gchar *data = NULL;
        gsize len;

        if (!g_file_get_contents(machine->firmware, &data, &len, NULL) ||
            len > 8 * MiB) {
            error_report("cannot load image '%s'", machine->firmware);
            exit(1);
        }
        memcpy(memory_region_get_ram_ptr(&s->ram), data, len);
    }

    s->io_log = g_malloc0(6 * IO_LOG_MAX);
    s->latch[0] = 0x1234;
    s->latch[1] = 0x0000;
    s->latch[2] = 0x5678;
    s->cpu = Z8000_CPU(cpu_create(machine->cpu_type));
    s->cpu->io_ops = &test_io_ops;
    s->cpu->io_opaque = s;
    qemu_register_reset(test_cpu_reset, s->cpu);
    cpu_reset(CPU(s->cpu));
}

static char *test_get_dump(Object *obj, Error **errp)
{
    return g_strdup(Z8000_TEST_MACHINE(obj)->dump);
}

static void test_set_dump(Object *obj, const char *value, Error **errp)
{
    Z8000TestState *s = Z8000_TEST_MACHINE(obj);

    g_free(s->dump);
    s->dump = g_strdup(value);
}

static void z8000_test_instance_init(Object *obj)
{
    Z8000TestState *s = Z8000_TEST_MACHINE(obj);

    s->dump_size = 64 * KiB;
    object_property_add_uint32_ptr(obj, "dump-size", &s->dump_size,
                                   OBJ_PROP_FLAG_READWRITE);
}

static void z8000_test_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "Z8000 CPU test machine";
    mc->init = z8000_test_init;
    mc->default_cpu_type = Z8000_CPU_TYPE_NAME("z8002");
    mc->default_cpus = 1;
    mc->max_cpus = 1;
    mc->no_floppy = 1;
    mc->no_cdrom = 1;
    mc->no_parallel = 1;
    object_class_property_add_str(oc, "dump", test_get_dump, test_set_dump);
    object_class_property_set_description(oc, "dump",
                                          "file written when the guest halts");
}

static const TypeInfo z8000_test_types[] = {
    {
        .name = TYPE_Z8000_TEST_MACHINE,
        .parent = TYPE_MACHINE,
        .instance_size = sizeof(Z8000TestState),
        .instance_init = z8000_test_instance_init,
        .class_init = z8000_test_class_init,
    },
};

DEFINE_TYPES(z8000_test_types)
