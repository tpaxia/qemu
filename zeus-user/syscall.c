/*
 * ZEUS user-mode emulation: system calls
 *
 * Calling convention (see abi/ZEUS-ABI.md in the Zeus_emulator project):
 * the call number is the low byte of the SC instruction, arguments are
 * words in R0 onwards, results come back in R4 (R4:R5 for a long or for a
 * second value), and an error is reported by setting carry with the error
 * number in R4.  A pointer is one word in a non-segmented program and two
 * in a segmented one, so the argument registers of a call differ between
 * the two; a long is two words in both.
 *
 * Every call is implemented with POSIX interfaces; nothing is passed
 * through to the host kernel unchanged.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu.h"
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <termios.h>
#include <utime.h>

/* ZEUS error numbers that the calls here can return */
enum {
    Z_EPERM = 1, Z_ENOENT = 2, Z_ESRCH = 3, Z_EINTR = 4, Z_EIO = 5,
    Z_ENXIO = 6, Z_E2BIG = 7, Z_ENOEXEC = 8, Z_EBADF = 9, Z_ECHILD = 10,
    Z_EAGAIN = 11, Z_ENOMEM = 12, Z_EACCES = 13, Z_EFAULT = 14,
    Z_ENOTBLK = 15, Z_EBUSY = 16, Z_EEXIST = 17, Z_EXDEV = 18,
    Z_ENODEV = 19, Z_ENOTDIR = 20, Z_EISDIR = 21, Z_EINVAL = 22,
    Z_ENFILE = 23, Z_EMFILE = 24, Z_ENOTTY = 25, Z_ETXTBSY = 26,
    Z_EFBIG = 27, Z_ENOSPC = 28, Z_ESPIPE = 29, Z_EROFS = 30,
    Z_EMLINK = 31, Z_EPIPE = 32, Z_EDOM = 33, Z_ERANGE = 34,
    Z_ESEGNO = 36,      /* mkseg: no such segment number to give */
};

/* ZEUS open flags (fcntl.h) */
#define Z_O_ACCMODE 3
#define Z_O_NDELAY  00004
#define Z_O_APPEND  00010
#define Z_O_CREAT   00400
#define Z_O_TRUNC   01000
#define Z_O_EXCL    02000

/* ZEUS file types (sys/stat.h) */
#define Z_S_IFDIR 0040000
#define Z_S_IFCHR 0020000
#define Z_S_IFBLK 0060000
#define Z_S_IFREG 0100000
#define Z_S_IFIFO 0010000

/* ioctl requests used by the C library's stty and gtty */
#define Z_TIOCGETP 0x7408
#define Z_TIOCSETP 0x7409

static const char * const call_names[] = {
    [0] = "sigreturn", [1] = "exit", [2] = "fork", [3] = "read",
    [4] = "write", [5] = "open", [6] = "close", [7] = "wait", [8] = "creat",
    [9] = "link", [10] = "unlink", [11] = "exec", [12] = "chdir",
    [13] = "time", [14] = "mknod", [15] = "chmod", [16] = "chown",
    [17] = "break", [18] = "stat", [19] = "seek", [20] = "getpid",
    [21] = "mount", [22] = "umount", [23] = "setuid", [24] = "getuid",
    [25] = "stime", [26] = "ptrace", [27] = "alarm", [28] = "fstat",
    [29] = "pause", [30] = "utime", [31] = "stty", [32] = "gtty",
    [33] = "access", [34] = "nice", [35] = "ftime", [36] = "sync",
    [37] = "kill", [38] = "fcntl", [39] = "setpgrp", [40] = "bpt",
    [41] = "dup", [42] = "pipe", [43] = "times", [44] = "profil",
    [45] = "ssgbrk", [46] = "setgid", [47] = "getgid", [48] = "sig",
    [49] = "lkdata", [50] = "unlk", [51] = "acct", [52] = "sprofil",
    [53] = "lock", [54] = "ioctl", [55] = "mkseg", [56] = "sgstat",
    [57] = "utssys", [58] = "sptrace", [59] = "exece", [60] = "umask",
    [61] = "chroot", [62] = "mdmctl", [63] = "nosys", [64] = "ulimit",
    [65] = "sread", [66] = "swrite", [67] = "getsw",
};

/*
 * Arguments of each call: i a word, l a long, p a pointer.  Calls not
 * listed take none, or are not implemented.
 */
static const char * const call_args[68] = {
    [1] = "i", [3] = "ipi", [4] = "ipi", [5] = "pii", [6] = "i",
    [8] = "pi", [9] = "pp", [10] = "p", [11] = "pp", [12] = "p",
    [14] = "pii", [15] = "pi", [16] = "pii", [17] = "p", [18] = "pp",
    [19] = "ili", [23] = "i", [25] = "l", [27] = "i", [28] = "ip",
    [30] = "pp", [33] = "pi", [34] = "i", [35] = "p", [37] = "ii",
    [38] = "iii", [39] = "i", [41] = "ii", [43] = "p", [45] = "ii",
    [46] = "i", [48] = "ip", [54] = "iip", [55] = "ii", [56] = "p",
    [57] = "pii", [59] = "ppp", [60] = "i", [61] = "p",
};

static int host_to_zeus_errno(int e)
{
    switch (e) {
    case EPERM:   return Z_EPERM;
    case ENOENT:  return Z_ENOENT;
    case ESRCH:   return Z_ESRCH;
    case EINTR:   return Z_EINTR;
    case EIO:     return Z_EIO;
    case ENXIO:   return Z_ENXIO;
    case E2BIG:   return Z_E2BIG;
    case ENOEXEC: return Z_ENOEXEC;
    case EBADF:   return Z_EBADF;
    case ECHILD:  return Z_ECHILD;
    case EAGAIN:  return Z_EAGAIN;
    case ENOMEM:  return Z_ENOMEM;
    case EACCES:  return Z_EACCES;
    case EFAULT:  return Z_EFAULT;
    case ENOTBLK: return Z_ENOTBLK;
    case EBUSY:   return Z_EBUSY;
    case EEXIST:  return Z_EEXIST;
    case EXDEV:   return Z_EXDEV;
    case ENODEV:  return Z_ENODEV;
    case ENOTDIR: return Z_ENOTDIR;
    case EISDIR:  return Z_EISDIR;
    case EINVAL:  return Z_EINVAL;
    case ENFILE:  return Z_ENFILE;
    case EMFILE:  return Z_EMFILE;
    case ENOTTY:  return Z_ENOTTY;
    case ETXTBSY: return Z_ETXTBSY;
    case EFBIG:   return Z_EFBIG;
    case ENOSPC:  return Z_ENOSPC;
    case ESPIPE:  return Z_ESPIPE;
    case EROFS:   return Z_EROFS;
    case EMLINK:  return Z_EMLINK;
    case EPIPE:   return Z_EPIPE;
    case EDOM:    return Z_EDOM;
    case ERANGE:  return Z_ERANGE;
    case ENAMETOOLONG: return Z_ENOENT;
    default:      return Z_EIO;
    }
}

/* ---- results ---- */

static void ret_ok(CPUZ8000State *env, uint32_t r4)
{
    env->regs[4] = r4 & 0xffff;
    env->fcw &= ~F_C;
}

static void ret_long(CPUZ8000State *env, uint32_t v)
{
    env->regs[4] = v >> 16;
    env->regs[5] = v & 0xffff;
    env->fcw &= ~F_C;
}

static void ret_err(CPUZ8000State *env, int zerr)
{
    env->regs[4] = zerr;
    env->regs[5] = 0;
    env->fcw |= F_C;
}

/* Result of a host call returning -1 with errno on failure. */
static void ret_host(CPUZ8000State *env, long r)
{
    if (r < 0) {
        ret_err(env, host_to_zeus_errno(errno));
    } else {
        ret_ok(env, r);
    }
}

/* Result of an fs.c call: a value, or a negative host errno. */
static void ret_fs(CPUZ8000State *env, int r)
{
    if (r < 0) {
        ret_err(env, host_to_zeus_errno(-r));
    } else {
        ret_ok(env, r);
    }
}

/* ---- individual calls ---- */

static void put16(uint8_t *p, uint32_t v)
{
    stw_be_p(p, v);
}

/* stat and fstat: ZEUS struct stat is 30 bytes */
static void do_stat(CPUZ8000State *env, const char *gpath, int fd,
                    uint32_t buf)
{
    uint8_t tmp[30];
    uint8_t *p;
    int r = gpath ? zeus_fs_stat(gpath, tmp) : zeus_fs_fstat(fd, tmp);

    if (r < 0) {
        ret_err(env, host_to_zeus_errno(-r));
        return;
    }
    p = zeus_data_ptr(env, buf, sizeof(tmp), true);
    if (!p) {
        ret_err(env, Z_EFAULT);
        return;
    }
    memcpy(p, tmp, sizeof(tmp));
    ret_ok(env, 0);
}

static void do_open(CPUZ8000State *env, uint32_t path_addr, uint32_t zflags,
                    uint32_t mode)
{
    g_autofree char *gpath = zeus_data_string(env, path_addr);
    int flags;

    if (!gpath) {
        ret_err(env, Z_EFAULT);
        return;
    }
    switch (zflags & Z_O_ACCMODE) {
    case 0:
        flags = O_RDONLY;
        break;
    case 1:
        flags = O_WRONLY;
        break;
    default:
        flags = O_RDWR;
        break;
    }
    if (zflags & Z_O_NDELAY) {
        flags |= O_NONBLOCK;
    }
    if (zflags & Z_O_APPEND) {
        flags |= O_APPEND;
    }
    if (zflags & Z_O_CREAT) {
        flags |= O_CREAT;
    }
    if (zflags & Z_O_TRUNC) {
        flags |= O_TRUNC;
    }
    if (zflags & Z_O_EXCL) {
        flags |= O_EXCL;
    }
    ret_fs(env, zeus_fs_open(gpath, flags, mode & 07777));
}

/* fcntl(fd, cmd, arg) */
static void do_fcntl(CPUZ8000State *env, int fd, uint32_t cmd, uint32_t arg)
{
    int r, fl;

    switch (cmd) {
    case 0: /* F_DUPFD */
        r = fcntl(fd, F_DUPFD, (int)arg);
        if (r >= 0) {
            zeus_fs_dup(fd, r);
        }
        ret_host(env, r);
        break;
    case 1: /* F_GETFD */
        ret_host(env, fcntl(fd, F_GETFD));
        break;
    case 2: /* F_SETFD */
        ret_host(env, fcntl(fd, F_SETFD, arg & 1 ? FD_CLOEXEC : 0));
        break;
    case 3: /* F_GETFL */
        fl = fcntl(fd, F_GETFL);
        if (fl < 0) {
            ret_host(env, fl);
            break;
        }
        r = (fl & O_ACCMODE) == O_RDONLY ? 0 :
            (fl & O_ACCMODE) == O_WRONLY ? 1 : 2;
        r |= (fl & O_NONBLOCK) ? Z_O_NDELAY : 0;
        r |= (fl & O_APPEND) ? Z_O_APPEND : 0;
        ret_ok(env, r);
        break;
    case 4: /* F_SETFL */
        fl = fcntl(fd, F_GETFL);
        if (fl >= 0) {
            fl &= ~(O_NONBLOCK | O_APPEND);
            fl |= (arg & Z_O_NDELAY) ? O_NONBLOCK : 0;
            fl |= (arg & Z_O_APPEND) ? O_APPEND : 0;
            fl = fcntl(fd, F_SETFL, fl);
        }
        ret_host(env, fl < 0 ? -1 : 0);
        break;
    default:
        ret_err(env, Z_EINVAL);
        break;
    }
}

static void do_ioctl(CPUZ8000State *env, int fd, uint32_t req, uint32_t arg)
{
    struct termios tio;
    uint8_t *p;

    switch (req) {
    case Z_TIOCGETP:
        if (tcgetattr(fd, &tio) < 0) {
            ret_err(env, errno == EBADF ? Z_EBADF : Z_ENOTTY);
            return;
        }
        p = zeus_data_ptr(env, arg, 6, true);
        if (!p) {
            ret_err(env, Z_EFAULT);
            return;
        }
        /* struct sgttyb: speeds (B9600 = 13), erase, kill, flags */
        p[0] = 13;
        p[1] = 13;
        p[2] = tio.c_cc[VERASE];
        p[3] = tio.c_cc[VKILL];
        put16(p + 4, 0x00d8);   /* ECHO | CRMOD | ANYP */
        ret_ok(env, 0);
        return;
    default:
        ret_err(env, isatty(fd) ? Z_EINVAL : Z_ENOTTY);
        return;
    }
}

/* ---- segments of a segmented program ---- */

/* The table entry of a segment that data references can reach. */
static struct zeus_seg *find_seg(struct image_info *info, uint32_t no)
{
    for (int i = 0; i < info->nsegs; i++) {
        if (info->segs[i].no == no && !info->segs[i].code) {
            return &info->segs[i];
        }
    }
    return NULL;
}

/*
 * break(address).  With a null address a segmented program gets the end
 * of its last data segment; otherwise the address names a segment and its
 * new end.
 */
static void do_break(CPUZ8000State *env, TaskState *ts, uint32_t addr)
{
    struct image_info *info = ts->info;
    struct zeus_seg *sg = NULL;

    if (!info->segmented) {
        /* the stack occupies the top of the space */
        if (addr >= (env->regs[15] & 0xffff) - 256) {
            ret_err(env, Z_ENOMEM);
        } else {
            ts->brk = addr;
            ret_ok(env, 0);
        }
        return;
    }
    if (addr == 0) {
        for (int i = 0; i < info->nsegs; i++) {
            if (!info->segs[i].code) {
                sg = &info->segs[i];
            }
        }
        if (sg) {
            ret_long(env, (sg->no << 24) | (sg->size & 0xffff));
            return;
        }
    } else {
        sg = find_seg(info, addr >> 16);
        if (!sg) {
            ret_err(env, Z_ENOMEM);
            return;
        }
        sg->size = ROUND_UP(addr & 0xffff, 256);
    }
    env->fcw &= ~F_C;
}

/* ssgbrk(segment, increment): the segment's previous end */
static void do_ssgbrk(CPUZ8000State *env, struct image_info *info,
                      uint32_t no, uint32_t incr)
{
    struct zeus_seg *sg = find_seg(info, no);
    uint32_t old;

    if (!info->segmented || !sg) {
        ret_err(env, Z_ENOMEM);
        return;
    }
    old = sg->size;
    incr = ROUND_UP(incr, 256);
    if (old + incr > ZEUS_SPACE_SIZE) {
        ret_err(env, Z_ENOMEM);
        return;
    }
    sg->size = old + incr;
    ret_long(env, (no << 24) | (old & 0xffff));
}

/*
 * mkseg(segment, size): a new data segment; segment 0 asks for the first
 * free number from 4 up.  Returns the segment's address.
 */
static void do_mkseg(CPUZ8000State *env, struct image_info *info,
                     uint32_t no, uint32_t size)
{
    struct zeus_seg *sg;

    no &= 0x7f;
    if (!info->segmented) {
        ret_err(env, Z_EINVAL);
        return;
    }
    if (no == 0) {
        for (no = 4; no < ZEUS_MAX_SEGS; no++) {
            bool used = no == info->stack_seg;

            for (int i = 0; i < info->nsegs; i++) {
                used |= info->segs[i].no == no;
            }
            if (!used) {
                break;
            }
        }
    } else if (find_seg(info, no) || no == info->stack_seg) {
        no = ZEUS_MAX_SEGS;
    }
    if (no == ZEUS_MAX_SEGS) {
        ret_err(env, Z_ESEGNO);
        return;
    }
    if (info->nsegs == ZEUS_MAX_SEGS) {
        ret_err(env, Z_ENOMEM);
        return;
    }
    sg = &info->segs[info->nsegs++];
    sg->no = no;
    sg->code = false;
    sg->code_size = 0;
    sg->size = ROUND_UP(size, 256);
    zeus_map_space(info->data_offset | (no << 16));
    ret_long(env, no << 24);
}

/*
 * sgstat(buf): ten entries of segment number and size for the segments
 * holding instructions, the unused ones marked with segment 0xff.
 */
static void do_sgstat(CPUZ8000State *env, struct image_info *info,
                      uint32_t buf)
{
    uint8_t *p = zeus_data_ptr(env, buf, 40, true);
    int n = 0;

    if (!p) {
        ret_err(env, Z_EFAULT);
        return;
    }
    for (int i = 0; i < info->nsegs && n < 10; i++) {
        struct zeus_seg *sg = &info->segs[i];
        uint32_t size = ROUND_UP(sg->code_size, 256);

        if (sg->code_size == 0) {
            continue;
        }
        if (!info->split_id) {
            /* one entry, for the last such segment */
            n = 0;
        }
        p[4 * n] = sg->no;
        p[4 * n + 1] = 0;
        put16(p + 4 * n + 2, size == ZEUS_SPACE_SIZE ? 0xfffe : size);
        n++;
    }
    for (; n < 10; n++) {
        p[4 * n] = 0xff;
        p[4 * n + 1] = 0;
        put16(p + 4 * n + 2, 0);
    }
    ret_ok(env, 0);
}

/*
 * The trace goes to a private copy of standard error, taken before the
 * program can close or redirect descriptor 2.
 */
static FILE *trace_file(void)
{
    static FILE *f;

    if (!f) {
        int fd = fcntl(2, F_DUPFD_CLOEXEC, 100);

        f = fd >= 0 ? fdopen(fd, "w") : stderr;
        setvbuf(f, NULL, _IONBF, 0);
    }
    return f;
}

void zeus_syscall(CPUZ8000State *env, int num)
{
    CPUState *cs = env_cpu(env);
    TaskState *ts = get_task_state(cs);
    bool segmented = ts->info->segmented;
    uint32_t arg[4] = { env->regs[0], env->regs[1], env->regs[2],
                        env->regs[3] };
    uint32_t a0, a1, a2;
    g_autofree char *gpath = NULL;
    g_autofree char *path = NULL;
    void *p;
    long r;

    if (num > 67) {
        num = 63;
    }
    if (call_args[num]) {
        int w = 0, n = 0;

        memset(arg, 0, sizeof(arg));
        for (const char *t = call_args[num]; *t; t++, n++) {
            if (*t == 'i' || (*t == 'p' && !segmented)) {
                arg[n] = env->regs[w++];
            } else {
                arg[n] = ((uint32_t)env->regs[w] << 16) | env->regs[w + 1];
                if (*t == 'p') {
                    arg[n] = zeus_long_to_ptr(arg[n]);
                }
                w += 2;
            }
        }
    }
    a0 = arg[0];
    a1 = arg[1];
    a2 = arg[2];
    if (do_strace) {
        fprintf(trace_file(), "%d %s(%#x, %#x, %#x, %#x)", getpid(),
                call_names[num], a0, a1, a2, arg[3]);
    }

    switch (num) {
    case 0: /* return from a signal handler */
        zeus_sigreturn(env);
        if (do_strace) {
            fprintf(trace_file(), "\n");
        }
        return;

    case 2: /* fork */
        zeus_fork(env);
        break;

    case 7: /* wait: pid in R4, status in R5 */
        r = zeus_wait(env);
        if (r) {
            ret_err(env, host_to_zeus_errno(r));
        } else {
            env->fcw &= ~F_C;
        }
        break;

    case 11: /* exec(path, argv) */
    case 59: /* exece(path, argv, envp) */
        r = zeus_exec(env, a0, a1, num == 59 ? a2 : 0);
        if (r) {
            ret_err(env, host_to_zeus_errno(r));
        } else {
            env->fcw &= ~F_C;   /* an overlay: the program carries on */
        }
        break;

    case 29: /* pause */
        pause();
        ret_err(env, Z_EINTR);
        break;

    case 37: /* kill(pid, sig) */
        r = zeus_kill((int16_t)a0, a1);
        if (r) {
            ret_err(env, host_to_zeus_errno(r));
        } else {
            ret_ok(env, 0);
        }
        break;

    case 39: /* setpgrp: R0 = 1 sets, 0 reads */
        if (a0) {
            setpgid(0, 0);
        }
        ret_ok(env, zeus_pid(getpgrp()));
        break;

    case 1: /* exit */
        if (do_strace) {
            fprintf(trace_file(), "\n");
        }
        exit(a0 & 0xff);

    case 3: /* read(fd, buf, count) */
        p = zeus_data_ptr(env, a1, a2, true);
        if (!p) {
            ret_err(env, Z_EFAULT);
            break;
        }
        ret_host(env, read((int16_t)a0, p, a2));
        break;

    case 4: /* write(fd, buf, count) */
        p = zeus_data_ptr(env, a1, a2, false);
        if (!p) {
            ret_err(env, Z_EFAULT);
            break;
        }
        ret_host(env, write((int16_t)a0, p, a2));
        break;

    case 5: /* open(path, flags, mode) */
        do_open(env, a0, a1, a2);
        break;

    case 6: /* close(fd) */
        r = close((int16_t)a0);
        if (r == 0) {
            zeus_fs_close((int16_t)a0);
        }
        ret_host(env, r);
        break;

    case 8: /* creat(path, mode) */
        do_open(env, a0, 1 | Z_O_CREAT | Z_O_TRUNC, a1);
        break;

    case 9: /* link(old, new) */
        gpath = zeus_data_string(env, a0);
        path = zeus_data_string(env, a1);
        if (!gpath || !path) {
            ret_err(env, Z_EFAULT);
            break;
        }
        ret_fs(env, zeus_fs_link(gpath, path));
        break;

    case 10: /* unlink(path) */
    case 12: /* chdir(path) */
    case 14: /* mknod(path, mode, dev) */
    case 15: /* chmod(path, mode) */
    case 16: /* chown(path, uid, gid) */
    case 18: /* stat(path, buf) */
    case 30: /* utime(path, times) */
    case 33: /* access(path, mode) */
    case 61: /* chroot(path) */
        gpath = zeus_data_string(env, a0);
        if (!gpath) {
            ret_err(env, Z_EFAULT);
            break;
        }
        switch (num) {
        case 10:
            ret_fs(env, zeus_fs_unlink(gpath));
            break;
        case 12:
            ret_fs(env, zeus_fs_chdir(gpath));
            break;
        case 14:
            if ((a1 & 0170000) == Z_S_IFIFO) {
                path = zeus_host_path(gpath);
                ret_host(env, mkfifo(path, a1 & 0777));
            } else {
                /* device nodes cannot be created in a host directory */
                ret_err(env, Z_EPERM);
            }
            break;
        case 15:
            ret_fs(env, zeus_fs_chmod(gpath, a1));
            break;
        case 16:
            ret_fs(env, zeus_fs_chown(gpath, a1, a2));
            break;
        case 18:
            do_stat(env, gpath, -1, a1);
            break;
        case 30:
            {
                struct utimbuf ut;
                uint8_t *tp = a1 ? zeus_data_ptr(env, a1, 8, false) : NULL;

                path = zeus_host_path(gpath);
                if (tp) {
                    ut.actime = ldl_be_p(tp);
                    ut.modtime = ldl_be_p(tp + 4);
                }
                ret_host(env, utime(path, tp ? &ut : NULL));
            }
            break;
        case 33:
            ret_fs(env, zeus_fs_access(gpath, a1 & 7));
            break;
        default:
            ret_err(env, Z_EPERM);
            break;
        }
        break;

    case 13: /* time() */
        ret_long(env, time(NULL));
        break;

    case 17: /* break(addr) */
        do_break(env, ts, a0);
        break;

    case 45: /* ssgbrk(segment, increment) */
        do_ssgbrk(env, ts->info, a0, a1);
        break;

    case 55: /* mkseg(segment, size) */
        do_mkseg(env, ts->info, a0, a1);
        break;

    case 56: /* sgstat(buf) */
        do_sgstat(env, ts->info, a0);
        break;

    case 19: /* seek(fd, long offset, whence) */
        {
            off_t off = (int32_t)a1;
            off_t pos = lseek((int16_t)a0, off, a2 == 0 ? SEEK_SET :
                              a2 == 1 ? SEEK_CUR : SEEK_END);
            if (pos < 0) {
                ret_err(env, host_to_zeus_errno(errno));
            } else {
                ret_long(env, pos);
            }
        }
        break;

    case 20: /* getpid: pid and parent pid */
        env->regs[5] = zeus_pid(getppid());
        ret_ok(env, zeus_pid(getpid()));
        break;

    case 23: /* setuid(uid) */
    case 46: /* setgid(gid) */
        /* one fixed identity; accept and ignore */
        ret_ok(env, 0);
        break;

    case 24: /* getuid: real and effective */
        env->regs[5] = ZEUS_UID;
        ret_ok(env, ZEUS_UID);
        break;

    case 47: /* getgid: real and effective */
        env->regs[5] = ZEUS_GID;
        ret_ok(env, ZEUS_GID);
        break;

    case 25: /* stime */
        ret_err(env, Z_EPERM);
        break;

    case 34: /* nice(incr) */
        ret_ok(env, 0);
        break;

    case 35: /* ftime(struct timeb *): time, ms, minutes west, dst flag */
        {
            struct timeval tv;
            struct tm tm;
            time_t now;
            uint8_t *tp = zeus_data_ptr(env, a0, 10, true);

            if (!tp) {
                ret_err(env, Z_EFAULT);
                break;
            }
            gettimeofday(&tv, NULL);
            now = tv.tv_sec;
            localtime_r(&now, &tm);
            stl_be_p(tp, tv.tv_sec);
            stw_be_p(tp + 4, tv.tv_usec / 1000);
            stw_be_p(tp + 6, -(tm.tm_gmtoff - (tm.tm_isdst > 0 ? 3600 : 0))
                             / 60);
            stw_be_p(tp + 8, tm.tm_isdst > 0);
            ret_ok(env, 0);
        }
        break;

    case 38: /* fcntl(fd, cmd, arg) */
        do_fcntl(env, (int16_t)a0, a1, a2);
        break;

    case 42: /* pipe: read end in R4, write end in R5 */
        {
            int fds[2];

            if (pipe(fds) < 0) {
                ret_err(env, host_to_zeus_errno(errno));
            } else {
                env->regs[5] = fds[1];
                ret_ok(env, fds[0]);
            }
        }
        break;

    case 43: /* times(struct tms *): four longs, in 1/60 s */
        {
            struct tms t;
            long hz = sysconf(_SC_CLK_TCK);
            uint8_t *tp = zeus_data_ptr(env, a0, 16, true);

            if (!tp) {
                ret_err(env, Z_EFAULT);
                break;
            }
            times(&t);
            stl_be_p(tp, t.tms_utime * 60 / hz);
            stl_be_p(tp + 4, t.tms_stime * 60 / hz);
            stl_be_p(tp + 8, t.tms_cutime * 60 / hz);
            stl_be_p(tp + 12, t.tms_cstime * 60 / hz);
            ret_long(env, 0);
        }
        break;

    case 27: /* alarm(seconds) */
        ret_ok(env, alarm(a0));
        break;

    case 28: /* fstat(fd, buf) */
        do_stat(env, NULL, (int16_t)a0, a1);
        break;

    case 36: /* sync */
        sync();
        ret_ok(env, 0);
        break;

    case 41: /* dup(fd) and dup2(fd | 0100, newfd) */
        if (a0 & 0100) {
            r = dup2(a0 & 077, (int16_t)a1);
        } else {
            r = dup((int16_t)a0);
        }
        if (r >= 0) {
            zeus_fs_dup(a0 & 077, r);
        }
        ret_host(env, r);
        break;

    case 48: /* sig(signo, handler): the previous value in R4 */
        {
            bool ok;
            uint32_t old = zeus_sig(a0, a1, &ok);

            if (!ok) {
                ret_err(env, Z_EINVAL);
            } else if (segmented) {
                ret_long(env, zeus_ptr_to_long(old));
            } else {
                ret_ok(env, old);
            }
        }
        break;

    case 54: /* ioctl(fd, request, arg) */
        do_ioctl(env, (int16_t)a0, a1, a2);
        break;

    case 57: /* utssys(buf, arg, function) */
        if (a2 == 0) {
            /* uname: four nine-byte strings */
            static const char uts[4][9] = { "ZEUS", "zeus", "3.21", "3.21" };
            uint8_t *up = zeus_data_ptr(env, a0, sizeof(uts), true);

            if (!up) {
                ret_err(env, Z_EFAULT);
                break;
            }
            memcpy(up, uts, sizeof(uts));
            ret_ok(env, 0);
        } else if (a2 == 2) {
            /* ustat: free blocks (long), free inodes, name, pack name */
            uint8_t *up = zeus_data_ptr(env, a0, 18, true);

            if (!up) {
                ret_err(env, Z_EFAULT);
                break;
            }
            memset(up, 0, 18);
            stl_be_p(up, 100000);
            stw_be_p(up + 4, 10000);
            ret_ok(env, 0);
        } else {
            ret_err(env, Z_EINVAL);
        }
        break;

    case 60: /* umask(mask) */
        ret_ok(env, umask(a0 & 0777));
        break;

    default:
        if (!do_strace) {
            fprintf(stderr, "qemu-" TARGET_NAME ": system call %d (%s) is "
                    "not implemented\n", num, call_names[num]);
        }
        ret_err(env, Z_EINVAL);
        break;
    }

    if (do_strace) {
        if (env->fcw & F_C) {
            fprintf(trace_file(), " = error %d\n", env->regs[4]);
        } else {
            fprintf(trace_file(), " = %#x\n", env->regs[4]);
        }
    }
}
