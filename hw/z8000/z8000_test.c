/*
 * Z8000 test machine: a CPU, 8 MiB of RAM and nothing else.
 *
 * The image given with -bios is loaded at address 0.  When the guest
 * executes HALT the machine writes the CPU state, a log of port output
 * and the first "dump-size" bytes of RAM to the file named by the "dump"
 * property, then exits.  It exists to compare the translator against a
 * reference interpreter and against captures from real hardware.
 *
 * Properties:
 *   dump=FILE       state dump written at HALT
 *   dump-size=N     bytes of RAM in the dump (default 64 KiB)
 *   ram-size=N      RAM size, a power of two; smaller sizes repeat across
 *                   the 8 MiB address space (default 8 MiB)
 *   io-model=NAME   "stock": the libz8000 standalone emulator's ports;
 *                   "z8ktest": the z8000_test harness, twelve word
 *                   registers at ports 0x0100-0x010B (normal I/O) and the
 *                   same addresses in special I/O
 *   split-id=on     separate instruction and data spaces: data references
 *                   go to a second RAM, loaded from data-image=FILE, and
 *                   the dump carries that RAM after the first
 *   init=FILE       start state applied after reset instead of the reset
 *                   vector, one item per line:
 *                     pc HEX | fcw HEX | reg N HEX |
 *                     io INDEX HEX | ioseq INDEX SLOT HEX
 *
 * With io-model=z8ktest the dump starts with "Z8KT" and carries the twelve
 * port registers after the control registers.
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

    MemoryRegion data_ram;
    uint32_t ram_size;
    bool split_id;
    char *data_image;
    char *io_model;
    char *init;
    bool z8ktest_io;
    /* z8ktest port registers and optional read sequences */
    uint16_t kt_reg[12];
    uint16_t kt_seq[12][4];
    int kt_seq_count[12];
    int kt_seq_pos[12];
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

/* ---- z8000_test harness port model ---- */

static bool kt_match(uint32_t port)
{
    return (port & 0xfff0) == 0x0100 && (port & 0x000e) <= 0x000a;
}

static int kt_index(uint32_t port, int special)
{
    return ((port >> 1) & 7) + (special ? 6 : 0);
}

static uint32_t kt_io_read(void *opaque, uint32_t port, int size, int special)
{
    Z8000TestState *s = opaque;
    uint32_t val;
    int idx;

    if (!kt_match(port)) {
        return size == 2 ? 0xffff : 0xff;
    }
    idx = kt_index(port, special);
    if (s->kt_seq_count[idx] > 0) {
        int pos = MIN(s->kt_seq_pos[idx], s->kt_seq_count[idx] - 1);

        val = s->kt_seq[idx][pos];
        if (s->kt_seq_pos[idx] < s->kt_seq_count[idx]) {
            s->kt_seq_pos[idx]++;
        }
    } else {
        val = s->kt_reg[idx];
    }
    if (size == 2) {
        return val;
    }
    return (port & 1) ? (val & 0xff) : (val >> 8);
}

static void kt_io_write(void *opaque, uint32_t port, uint32_t val, int size,
                        int special)
{
    Z8000TestState *s = opaque;
    int idx;

    if (!kt_match(port)) {
        return;
    }
    idx = kt_index(port, special);
    if (size == 2) {
        s->kt_reg[idx] = val;
    } else if (port & 1) {
        s->kt_reg[idx] = (s->kt_reg[idx] & 0xff00) | (val & 0xff);
    } else {
        s->kt_reg[idx] = (s->kt_reg[idx] & 0x00ff) | ((val & 0xff) << 8);
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
    fwrite(s->z8ktest_io ? "Z8KT" : "Z8KD", 1, 4, f);
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
    if (s->z8ktest_io) {
        for (int i = 0; i < 12; i++) {
            put16(f, s->kt_reg[i]);
        }
    }
    put16(f, s->io_count >> 16);
    put16(f, s->io_count);
    fwrite(s->io_log, 6, s->io_count, f);
    fwrite(memory_region_get_ram_ptr(&s->ram), 1, s->dump_size, f);
    if (s->split_id) {
        fwrite(memory_region_get_ram_ptr(&s->data_ram), 1, s->dump_size, f);
    }
    fclose(f);
    exit(0);
}

static const Z8000IOOps test_io_ops = {
    .read = test_io_read,
    .write = test_io_write,
    .halt = test_halt,
};

static const Z8000IOOps kt_io_ops = {
    .read = kt_io_read,
    .write = kt_io_write,
    .halt = test_halt,
};

/* Apply the start state from the "init" file, replacing the reset vector. */
static void test_apply_init(Z8000TestState *s)
{
    CPUZ8000State *env = &s->cpu->env;
    g_autofree gchar *text = NULL;
    g_auto(GStrv) lines = NULL;

    if (!s->init) {
        return;
    }
    if (!g_file_get_contents(s->init, &text, NULL, NULL)) {
        error_report("cannot read init file '%s'", s->init);
        exit(1);
    }
    lines = g_strsplit(text, "\n", -1);
    for (int i = 0; lines[i]; i++) {
        unsigned a, b, c;

        if (sscanf(lines[i], "pc %x", &a) == 1) {
            env->pc = a;
        } else if (sscanf(lines[i], "fcw %x", &a) == 1) {
            env->fcw = a & 0xffff;
        } else if (sscanf(lines[i], "reg %u %x", &a, &b) == 2 && a < 16) {
            env->regs[a] = b & 0xffff;
        } else if (sscanf(lines[i], "ioseq %u %u %x", &a, &b, &c) == 3 &&
                   a < 12 && b < 4) {
            s->kt_seq[a][b] = c;
            s->kt_seq_count[a] = MAX(s->kt_seq_count[a], (int)b + 1);
        } else if (sscanf(lines[i], "io %u %x", &a, &b) == 2 && a < 12) {
            s->kt_reg[a] = b;
        } else if (lines[i][0] && lines[i][0] != '#') {
            error_report("%s:%d: unrecognised line", s->init, i + 1);
            exit(1);
        }
    }
}

static void test_cpu_reset(void *opaque)
{
    Z8000TestState *s = opaque;

    s->cpu->env.data_tag = s->split_id ? Z8000_DATA_TAG : 0;
    cpu_reset(CPU(s->cpu));
    test_apply_init(s);
}

/* Map a RAM at base, repeated to fill 8 MiB when it is smaller. */
static void test_map_ram(Z8000TestState *s, MemoryRegion *ram,
                         const char *name, hwaddr base)
{
    int n = 8 * MiB / s->ram_size - 1;
    MemoryRegion *aliases = g_new(MemoryRegion, n);

    memory_region_init_ram(ram, NULL, name, s->ram_size, &error_fatal);
    memory_region_add_subregion(get_system_memory(), base, ram);
    for (int i = 0; i < n; i++) {
        memory_region_init_alias(&aliases[i], NULL, name, ram, 0,
                                 s->ram_size);
        memory_region_add_subregion(get_system_memory(),
                                    base + (hwaddr)(i + 1) * s->ram_size,
                                    &aliases[i]);
    }
}

static void test_load_image(Z8000TestState *s, MemoryRegion *ram,
                            const char *path)
{
    g_autofree gchar *data = NULL;
    gsize len;

    if (!path) {
        return;
    }
    if (!g_file_get_contents(path, &data, &len, NULL) || len > s->ram_size) {
        error_report("cannot load image '%s'", path);
        exit(1);
    }
    memcpy(memory_region_get_ram_ptr(ram), data, len);
}

static void z8000_test_init(MachineState *machine)
{
    Z8000TestState *s = Z8000_TEST_MACHINE(machine);

    if (!is_power_of_2(s->ram_size) || s->ram_size > 8 * MiB ||
        s->ram_size < 4 * KiB || s->dump_size > s->ram_size) {
        error_report("invalid ram-size or dump-size");
        exit(1);
    }
    test_map_ram(s, &s->ram, "z8000-test.ram", 0);
    if (s->split_id) {
        test_map_ram(s, &s->data_ram, "z8000-test.data-ram", Z8000_DATA_TAG);
        test_load_image(s, &s->data_ram, s->data_image);
    }
    s->z8ktest_io = s->io_model && !strcmp(s->io_model, "z8ktest");
    if (s->io_model && !s->z8ktest_io && strcmp(s->io_model, "stock")) {
        error_report("unknown io-model '%s'", s->io_model);
        exit(1);
    }

    test_load_image(s, &s->ram, machine->firmware);

    s->io_log = g_malloc0(6 * IO_LOG_MAX);
    s->latch[0] = 0x1234;
    s->latch[1] = 0x0000;
    s->latch[2] = 0x5678;
    s->cpu = Z8000_CPU(cpu_create(machine->cpu_type));
    s->cpu->io_ops = s->z8ktest_io ? &kt_io_ops : &test_io_ops;
    s->cpu->io_opaque = s;
    qemu_register_reset(test_cpu_reset, s);
    test_cpu_reset(s);
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

static char *test_get_io_model(Object *obj, Error **errp)
{
    return g_strdup(Z8000_TEST_MACHINE(obj)->io_model);
}

static void test_set_io_model(Object *obj, const char *value, Error **errp)
{
    Z8000TestState *s = Z8000_TEST_MACHINE(obj);

    g_free(s->io_model);
    s->io_model = g_strdup(value);
}

static char *test_get_data_image(Object *obj, Error **errp)
{
    return g_strdup(Z8000_TEST_MACHINE(obj)->data_image);
}

static void test_set_data_image(Object *obj, const char *value, Error **errp)
{
    Z8000TestState *s = Z8000_TEST_MACHINE(obj);

    g_free(s->data_image);
    s->data_image = g_strdup(value);
}

static bool test_get_split_id(Object *obj, Error **errp)
{
    return Z8000_TEST_MACHINE(obj)->split_id;
}

static void test_set_split_id(Object *obj, bool value, Error **errp)
{
    Z8000_TEST_MACHINE(obj)->split_id = value;
}

static char *test_get_init(Object *obj, Error **errp)
{
    return g_strdup(Z8000_TEST_MACHINE(obj)->init);
}

static void test_set_init(Object *obj, const char *value, Error **errp)
{
    Z8000TestState *s = Z8000_TEST_MACHINE(obj);

    g_free(s->init);
    s->init = g_strdup(value);
}

static void z8000_test_instance_init(Object *obj)
{
    Z8000TestState *s = Z8000_TEST_MACHINE(obj);

    s->dump_size = 64 * KiB;
    s->ram_size = 8 * MiB;
    object_property_add_uint32_ptr(obj, "dump-size", &s->dump_size,
                                   OBJ_PROP_FLAG_READWRITE);
    object_property_add_uint32_ptr(obj, "ram-size", &s->ram_size,
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
    object_class_property_add_str(oc, "io-model", test_get_io_model,
                                  test_set_io_model);
    object_class_property_set_description(oc, "io-model",
                                          "port model: stock or z8ktest");
    object_class_property_add_bool(oc, "split-id", test_get_split_id,
                                   test_set_split_id);
    object_class_property_set_description(oc, "split-id",
                                          "separate instruction and data RAM");
    object_class_property_add_str(oc, "data-image", test_get_data_image,
                                  test_set_data_image);
    object_class_property_set_description(oc, "data-image",
                                          "image loaded into the data RAM");
    object_class_property_add_str(oc, "init", test_get_init, test_set_init);
    object_class_property_set_description(oc, "init",
                                          "start state applied after reset");
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
