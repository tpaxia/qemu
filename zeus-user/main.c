/*
 * ZEUS user-mode emulation: main program and CPU loop
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/help-texts.h"
#include "qemu/accel.h"
#include "qemu-version.h"
#include "qapi/error.h"
#include "qemu.h"
#include "qemu/config-file.h"
#include "qemu/error-report.h"
#include "qemu/help_option.h"
#include "qemu/module.h"
#include "qemu/log.h"
#include "qemu/plugin.h"
#include "user/guest-base.h"
#include "user/cpu_loop.h"
#include "user/mmap.h"
#include "accel/accel-ops.h"
#include "accel/tcg/cpu-loop.h"
#include "tcg/startup.h"
#include "exec/log.h"
#include "exec/page-vary.h"
#include "trace/control.h"
#include "hw/core/cpu.h"

__thread CPUState *thread_cpu;
int do_strace;
const char *zeus_sysroot;

bool qemu_cpu_is_self(CPUState *cpu)
{
    return thread_cpu == cpu;
}

void fork_start(void)
{
    start_exclusive();
    mmap_fork_start();
    cpu_list_lock();
}

void fork_end(pid_t pid)
{
    bool child = pid == 0;

    mmap_fork_end(child);
    if (child) {
        qemu_init_cpu_list();
        get_task_state(thread_cpu)->ts_tid = qemu_get_thread_id();
    } else {
        cpu_list_unlock();
    }
    end_exclusive();
}

void cpu_loop(CPUZ8000State *env)
{
    CPUState *cs = env_cpu(env);
    TaskState *ts = get_task_state(cs);
    int trapnr;

    for (;;) {
        cpu_exec_start(cs);
        trapnr = cpu_exec(cs);
        cpu_exec_end(cs);
        qemu_process_cpu_events(cs);

        switch (trapnr) {
        case EXCP_Z8000_SC:
            if (ts->in_fpe) {
                zeus_fpe_call(env, env->op0 & 0xff);
            } else {
                zeus_syscall(env, env->op0 & 0xff);
            }
            break;
        case EXCP_INTERRUPT:
            break;
        case EXCP_ATOMIC:
            cpu_exec_step_atomic(cs);
            break;
        case EXCP_Z8000_EPU:
            /* executed by the ZEUS kernel's own software emulator */
            if (!zeus_fpe_enter(env)) {
                zeus_force_signal(env, TARGET_SIGILL,
                                  "floating-point instruction");
            }
            break;
        case EXCP_Z8000_PRIV:
            zeus_force_signal(env, TARGET_SIGILL, "illegal instruction");
            break;
        case EXCP_Z8000_SEGTRAP:
            if (ts->in_fpe) {
                error_report("memory fault inside the floating-point "
                             "emulator, address %06x", ts->fault_addr);
                exit(EXIT_FAILURE);
            }
            zeus_force_signal(env, TARGET_SIGSEGV, "memory fault");
            break;
        case EXCP_DEBUG:
            zeus_force_signal(env, TARGET_SIGTRAP, "breakpoint");
            break;
        default:
            fprintf(stderr, "qemu-" TARGET_NAME ": unexpected trap %d\n",
                    trapnr);
            exit(EXIT_FAILURE);
        }
        zeus_process_signals(env);
    }
}

static void usage(void)
{
    printf("qemu-" TARGET_NAME " version " QEMU_FULL_VERSION "\n"
           "usage: qemu-" TARGET_NAME " [options] program [arguments...]\n"
           "ZEUS (Zilog System 8000) user-mode emulator\n"
           "\n"
           "-L path           ZEUS root directory; absolute guest paths are\n"
           "                  looked up under it\n"
           "-E var=value      set a variable in the program's environment\n"
           "-0 name           pass name as the program's argv[0]\n"
           "-cpu model        select CPU (default " TARGET_DEFAULT_CPU_MODEL
           ")\n"
           "-strace           log system calls\n"
           "-d item1[,...]    enable logging of specified items\n"
           "-D logfile        write logs to 'logfile' (default stderr)\n"
           "-one-insn-per-tb  one guest instruction per translation block\n"
           "\n" QEMU_HELP_BOTTOM "\n");
    exit(1);
}

int main(int argc, char **argv)
{
    const char *cpu_model = TARGET_DEFAULT_CPU_MODEL;
    const char *log_file = NULL, *log_mask = NULL;
    bool one_insn = false;
    g_autoptr(GPtrArray) genv = g_ptr_array_new();
    struct image_info *info = g_new0(struct image_info, 1);
    struct zeus_binprm *bprm = g_new0(struct zeus_binprm, 1);
    g_autofree char *host_file = NULL;
    g_autoptr(GPtrArray) opts = g_ptr_array_new();
    const char *argv0 = NULL;
    const char *term;
    CPUZ8000State *env;
    TaskState *ts;
    CPUState *cpu;
    int optind = 1, rv;

    error_init(argv[0]);
    module_call_init(MODULE_INIT_TRACE);
    qemu_init_cpu_list();
    module_call_init(MODULE_INIT_QOM);
    qemu_add_opts(&qemu_trace_opts);

    if (zeus_env_is_exact()) {
        /* started by a ZEUS exec: the environment is the program's own */
        for (char **e = environ; *e; e++) {
            if (!zeus_env_is_internal(*e)) {
                g_ptr_array_add(genv, g_strdup(*e));
            }
        }
    } else {
        /* a small default environment; the host's would not fit in 64K */
        g_ptr_array_add(genv, g_strdup("PATH=:/bin:/usr/bin"));
        g_ptr_array_add(genv, g_strdup("HOME=/"));
        term = getenv("ZEUS_TERM");
        g_ptr_array_add(genv,
                        g_strdup_printf("TERM=%s", term ? term : "vt100"));
    }

    for (;;) {
        const char *r;

        if (optind >= argc) {
            break;
        }
        r = argv[optind];
        if (r[0] != '-') {
            break;
        }
        optind++;
        r++;
        if (!strcmp(r, "-")) {
            break;
        } else if (!strcmp(r, "L") && optind < argc) {
            /* options kept in opts are passed on when the program execs */
            zeus_sysroot = realpath(argv[optind++], NULL);
            if (!zeus_sysroot) {
                error_report("%s: %s", argv[optind - 1], strerror(errno));
                exit(1);
            }
            g_ptr_array_add(opts, (char *)"-L");
            g_ptr_array_add(opts, (char *)zeus_sysroot);
        } else if (!strcmp(r, "E") && optind < argc) {
            g_ptr_array_add(genv, g_strdup(argv[optind++]));
        } else if (!strcmp(r, "0") && optind < argc) {
            argv0 = argv[optind++];
        } else if (!strcmp(r, "cpu") && optind < argc) {
            cpu_model = argv[optind++];
            if (is_help_option(cpu_model)) {
                list_cpus();
                exit(0);
            }
            g_ptr_array_add(opts, (char *)"-cpu");
            g_ptr_array_add(opts, (char *)cpu_model);
        } else if (!strcmp(r, "d") && optind < argc) {
            log_mask = argv[optind++];
        } else if (!strcmp(r, "D") && optind < argc) {
            log_file = argv[optind++];
        } else if (!strcmp(r, "strace")) {
            do_strace = 1;
            g_ptr_array_add(opts, (char *)"-strace");
        } else if (!strcmp(r, "one-insn-per-tb")) {
            one_insn = true;
        } else {
            usage();
        }
    }
    if (optind >= argc) {
        usage();
    }
    g_ptr_array_add(genv, NULL);
    g_ptr_array_add(opts, NULL);
    zeus_proc_init(argv[0], (char **)opts->pdata);

    {
        int mask = 0;

        if (log_mask) {
            mask = qemu_str_to_log_mask(log_mask);
            if (!mask) {
                qemu_print_log_usage(stdout);
                exit(1);
            }
        }
        qemu_set_log_filename_flags(log_file, mask, &error_fatal);
    }
    if (!trace_init_backends()) {
        exit(1);
    }
    trace_init_file();

    {
        AccelState *accel = current_accel();
        AccelClass *ac = ACCEL_GET_CLASS(accel);

        accel_init_interfaces(ac);
        object_property_set_bool(OBJECT(accel), "one-insn-per-tb", one_insn,
                                 &error_abort);
        ac->init_machine(accel, NULL);
    }
    finalize_target_page_bits();

    cpu = cpu_create(parse_cpu_option(cpu_model));
    env = cpu_env(cpu);
    cpu_reset(cpu);
    thread_cpu = cpu;

    zeus_memory_init();
    zeus_fs_init();

    /* The program is named by a guest path when a root is given. */
    host_file = zeus_host_path(argv[optind]);
    bprm->filename = host_file;
    {
        const char *program = argv[optind];

        if (argv0) {
            argv[optind] = (char *)argv0;
        }
        rv = zeus_load(host_file, argv + optind, (char **)genv->pdata, env,
                       info);
        if (rv != 0) {
            error_report("%s: %s", program, strerror(-rv));
            exit(126);
        }
    }

    ts = g_new0(TaskState, 1);
    ts->info = info;
    ts->bprm = bprm;
    ts->brk = info->brk;
    ts->ts_tid = qemu_get_thread_id();
    cpu->opaque = ts;

    zeus_signal_init();
    tcg_prologue_init();

    cpu_loop(env);
    return 0;
}
