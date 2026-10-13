/*
 * ZEUS user-mode emulation: system calls
 *
 * Calling convention (see abi/ZEUS-ABI.md in the Zeus_emulator project):
 * the call number is the low byte of the SC instruction, arguments are in
 * R0-R3, results come back in R4 (R4:R5 for a long or for a second value),
 * and an error is reported by setting carry with the error number in R4.
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
#include <termios.h>

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

/*
 * Host path for a guest path: absolute paths are looked up under the ZEUS
 * root when one was given with -L; relative paths are left alone.
 */
char *zeus_host_path(const char *guest_path)
{
    if (zeus_sysroot && guest_path[0] == '/') {
        return g_strconcat(zeus_sysroot, guest_path, NULL);
    }
    return g_strdup(guest_path);
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

/* ---- individual calls ---- */

static void put16(uint8_t *p, uint32_t v)
{
    stw_be_p(p, v);
}

static void put32(uint8_t *p, uint32_t v)
{
    stl_be_p(p, v);
}

/* struct stat as laid out by ZEUS: 30 bytes */
static void do_stat(CPUZ8000State *env, int r, const struct stat *st,
                    uint32_t buf)
{
    uint8_t *p = zeus_data_ptr(env, buf, 30, true);
    uint32_t mode;

    if (r < 0) {
        ret_err(env, host_to_zeus_errno(errno));
        return;
    }
    if (!p) {
        ret_err(env, Z_EFAULT);
        return;
    }
    mode = st->st_mode & 07777;
    if (S_ISDIR(st->st_mode)) {
        mode |= Z_S_IFDIR;
    } else if (S_ISCHR(st->st_mode)) {
        mode |= Z_S_IFCHR;
    } else if (S_ISBLK(st->st_mode)) {
        mode |= Z_S_IFBLK;
    } else if (S_ISFIFO(st->st_mode)) {
        mode |= Z_S_IFIFO;
    } else {
        mode |= Z_S_IFREG;
    }
    put16(p + 0, st->st_dev);
    /* inode numbers are 16 bits and zero means "no entry" */
    put16(p + 2, (st->st_ino & 0xffff) ? st->st_ino : 1);
    put16(p + 4, mode);
    put16(p + 6, st->st_nlink);
    put16(p + 8, st->st_uid);
    put16(p + 10, st->st_gid);
    put16(p + 12, st->st_rdev);
    put32(p + 14, st->st_size);
    put32(p + 18, st->st_atime);
    put32(p + 22, st->st_mtime);
    put32(p + 26, st->st_ctime);
    ret_ok(env, 0);
}

static void do_open(CPUZ8000State *env, uint32_t path_addr, uint32_t zflags,
                    uint32_t mode)
{
    g_autofree char *gpath = zeus_data_string(env, path_addr);
    g_autofree char *path = NULL;
    int flags;

    if (!gpath) {
        ret_err(env, Z_EFAULT);
        return;
    }
    path = zeus_host_path(gpath);
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
    ret_host(env, open(path, flags, mode & 07777));
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

void zeus_syscall(CPUZ8000State *env, int num)
{
    CPUState *cs = env_cpu(env);
    TaskState *ts = get_task_state(cs);
    uint32_t a0 = env->regs[0], a1 = env->regs[1];
    uint32_t a2 = env->regs[2], a3 = env->regs[3];
    g_autofree char *gpath = NULL;
    g_autofree char *path = NULL;
    struct stat st;
    void *p;
    long r;

    if (num > 67) {
        num = 63;
    }
    if (do_strace) {
        fprintf(stderr, "%d %s(%#x, %#x, %#x, %#x)", getpid(),
                call_names[num], a0, a1, a2, a3);
    }

    switch (num) {
    case 1: /* exit */
        if (do_strace) {
            fprintf(stderr, "\n");
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
        ret_host(env, close((int16_t)a0));
        break;

    case 8: /* creat(path, mode) */
        do_open(env, a0, 1 | Z_O_CREAT | Z_O_TRUNC, a1);
        break;

    case 10: /* unlink(path) */
    case 12: /* chdir(path) */
    case 18: /* stat(path, buf) */
    case 33: /* access(path, mode) */
        gpath = zeus_data_string(env, a0);
        if (!gpath) {
            ret_err(env, Z_EFAULT);
            break;
        }
        path = zeus_host_path(gpath);
        if (num == 10) {
            ret_host(env, unlink(path));
        } else if (num == 12) {
            ret_host(env, chdir(path));
        } else if (num == 33) {
            ret_host(env, access(path, a1 & 7));
        } else {
            r = stat(path, &st);
            do_stat(env, r, &st, a1);
        }
        break;

    case 13: /* time() */
        ret_long(env, time(NULL));
        break;

    case 17: /* break(addr): the stack occupies the top of the space */
        if (a0 >= (env->regs[15] & 0xffff) - 256) {
            ret_err(env, Z_ENOMEM);
        } else {
            ts->brk = a0;
            ret_ok(env, 0);
        }
        break;

    case 19: /* seek(fd, long offset, whence) */
        {
            off_t off = (int32_t)((a1 << 16) | a2);
            off_t pos = lseek((int16_t)a0, off, a3 == 0 ? SEEK_SET :
                              a3 == 1 ? SEEK_CUR : SEEK_END);
            if (pos < 0) {
                ret_err(env, host_to_zeus_errno(errno));
            } else {
                ret_long(env, pos);
            }
        }
        break;

    case 20: /* getpid: pid and parent pid */
        env->regs[5] = getppid() & 0x7fff;
        ret_ok(env, getpid() & 0x7fff);
        break;

    case 24: /* getuid: real and effective */
        env->regs[5] = geteuid() & 0xffff;
        ret_ok(env, getuid() & 0xffff);
        break;

    case 47: /* getgid: real and effective */
        env->regs[5] = getegid() & 0xffff;
        ret_ok(env, getgid() & 0xffff);
        break;

    case 27: /* alarm(seconds) */
        ret_ok(env, alarm(a0));
        break;

    case 28: /* fstat(fd, buf) */
        r = fstat((int16_t)a0, &st);
        do_stat(env, r, &st, a1);
        break;

    case 36: /* sync */
        sync();
        ret_ok(env, 0);
        break;

    case 41: /* dup(fd) and dup2(fd | 0100, newfd) */
        if (a0 & 0100) {
            ret_host(env, dup2(a0 & 077, (int16_t)a1));
        } else {
            ret_host(env, dup((int16_t)a0));
        }
        break;

    case 48: /* sig(signo, handler): delivery is not implemented yet */
        ret_ok(env, 0);
        break;

    case 54: /* ioctl(fd, request, arg) */
        do_ioctl(env, (int16_t)a0, a1, a2);
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
            fprintf(stderr, " = error %d\n", env->regs[4]);
        } else {
            fprintf(stderr, " = %#x\n", env->regs[4]);
        }
    }
}
