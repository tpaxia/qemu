/*
 * ZEUS user-mode emulation: terminal control
 *
 * ZEUS has two sets of terminal calls: the Version 7 one (struct sgttyb
 * and struct tchars) and the System III one (struct termio).  Both are
 * translated to and from the host's termios, so the terminal's state
 * lives in the host and is shared with whatever else uses the terminal.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu.h"
#include <sys/ioctl.h>
#include <termios.h>

/* requests (sgtty.h, sys/ioctl.h) */
#define Z_TIOCHPCL  0x7402
#define Z_TIOCGETP  0x7408
#define Z_TIOCSETP  0x7409
#define Z_TIOCSETN  0x740a
#define Z_TIOCEXCL  0x740d
#define Z_TIOCNXCL  0x740e
#define Z_TIOCFLUSH 0x7410
#define Z_TIOCSETC  0x7411
#define Z_TIOCGETC  0x7412
#define Z_TCGETA    0x5401
#define Z_TCSETA    0x5402
#define Z_TCSETAW   0x5403
#define Z_TCSETAF   0x5404
#define Z_TCSBRK    0x5405
#define Z_TCXONC    0x5406
#define Z_TCFLSH    0x5407
#define Z_TCXCLUSE  0x540d
#define Z_TCNXCLUSE 0x540e
#define Z_FIOCLEX   0x6601
#define Z_FIONCLEX  0x6602

/* sgttyb mode flags */
#define Z_TANDEM 0000001
#define Z_CBREAK 0000002
#define Z_ECHO   0000010
#define Z_CRMOD  0000020
#define Z_RAW    0000040
#define Z_ANYP   0000300
#define Z_XTABS  0006000

/* termio c_lflag, c_cflag and c_cc */
#define Z_ICANON 0000002
#define Z_CBAUD  0000017
#define Z_CSIZE  0000060
#define Z_NCC    8
#define Z_VEOF   4
#define Z_VEOL   5

#define Z_ENOTTY 25
#define Z_EINVAL 22
#define Z_EFAULT 14
#define Z_EBADF  9

/* A flag bit in a ZEUS word and the host flag it stands for */
typedef struct {
    uint16_t z;
    tcflag_t h;
} FlagMap;

static const FlagMap iflags[] = {
    { 0000001, IGNBRK }, { 0000002, BRKINT }, { 0000004, IGNPAR },
    { 0000010, PARMRK }, { 0000020, INPCK }, { 0000040, ISTRIP },
    { 0000100, INLCR }, { 0000200, IGNCR }, { 0000400, ICRNL },
    { 0002000, IXON }, { 0004000, IXANY }, { 0010000, IXOFF },
};

static const FlagMap oflags[] = {
    { 0000001, OPOST }, { 0000004, ONLCR }, { 0000010, OCRNL },
    { 0000020, ONOCR }, { 0000040, ONLRET },
#ifdef OXTABS
    { 0014000, OXTABS },
#else
    { 0014000, TAB3 },
#endif
};

static const FlagMap cflags[] = {
    { 0000100, CSTOPB }, { 0000200, CREAD }, { 0000400, PARENB },
    { 0001000, PARODD }, { 0002000, HUPCL }, { 0004000, CLOCAL },
};

static const FlagMap lflags[] = {
    { 0000001, ISIG }, { 0000002, ICANON }, { 0000010, ECHO },
    { 0000020, ECHOE }, { 0000040, ECHOK }, { 0000100, ECHONL },
    { 0000200, NOFLSH },
};

static uint16_t flags_to_zeus(const FlagMap *map, int n, tcflag_t h)
{
    uint16_t z = 0;

    for (int i = 0; i < n; i++) {
        if ((h & map[i].h) == map[i].h) {
            z |= map[i].z;
        }
    }
    return z;
}

/* Change only the host flags ZEUS knows; the others stay as they were. */
static tcflag_t flags_to_host(const FlagMap *map, int n, uint16_t z,
                              tcflag_t h)
{
    for (int i = 0; i < n; i++) {
        if ((z & map[i].z) == map[i].z) {
            h |= map[i].h;
        } else {
            h &= ~map[i].h;
        }
    }
    return h;
}

/*
 * ZEUS speed codes, the same in both interfaces.  14 and 15 are the two
 * external clocks; a host speed ZEUS has no code for is reported as 9600
 * baud, which programs use only to work out padding.
 */
#define Z_B9600 13

static const speed_t speeds[14] = {
    B0, B50, B75, B110, B134, B150, B200, B300, B600, B1200, B1800, B2400,
    B4800, B9600,
};

static int speed_to_zeus(speed_t s)
{
    for (int i = 0; i < ARRAY_SIZE(speeds); i++) {
        if (speeds[i] == s) {
            return i;
        }
    }
    return Z_B9600;
}

/*
 * Set a speed only if the program asks for one other than what it was
 * told, so that handing back what it read leaves a faster line alone.
 */
static void set_speeds(struct termios *t, int in, int out)
{
    if (in < ARRAY_SIZE(speeds) && in != speed_to_zeus(cfgetispeed(t))) {
        cfsetispeed(t, speeds[in]);
    }
    if (out < ARRAY_SIZE(speeds) && out != speed_to_zeus(cfgetospeed(t))) {
        cfsetospeed(t, speeds[out]);
    }
}

/* A control character; ZEUS disables one with 0377. */
static uint8_t cc_to_zeus(cc_t c)
{
    return c == _POSIX_VDISABLE ? 0377 : c;
}

static cc_t cc_to_host(uint8_t c)
{
    return c == 0377 ? _POSIX_VDISABLE : c;
}

static int get_sgttyb(const struct termios *t, uint8_t *p)
{
    uint16_t flags = Z_ANYP;

    if (!(t->c_lflag & ICANON)) {
        flags |= (t->c_lflag & ISIG) ? Z_CBREAK : Z_RAW;
    }
    if (t->c_lflag & ECHO) {
        flags |= Z_ECHO;
    }
    if (t->c_iflag & ICRNL) {
        flags |= Z_CRMOD;
    }
    if (t->c_iflag & IXOFF) {
        flags |= Z_TANDEM;
    }
    flags |= flags_to_zeus(oflags + 5, 1, t->c_oflag) ? Z_XTABS : 0;
    p[0] = speed_to_zeus(cfgetispeed(t));
    p[1] = speed_to_zeus(cfgetospeed(t));
    p[2] = cc_to_zeus(t->c_cc[VERASE]);
    p[3] = cc_to_zeus(t->c_cc[VKILL]);
    stw_be_p(p + 4, flags);
    return 0;
}

static void set_sgttyb(struct termios *t, const uint8_t *p)
{
    uint16_t flags = lduw_be_p(p + 4);

    set_speeds(t, p[0] & 15, p[1] & 15);
    t->c_cc[VERASE] = cc_to_host(p[2]);
    t->c_cc[VKILL] = cc_to_host(p[3]);

    if (flags & Z_RAW) {
        /* every character is passed on as it is, in both directions */
        t->c_iflag &= ~(ICRNL | INLCR | IGNCR | IXON | IXANY | ISTRIP |
                        BRKINT);
        t->c_oflag &= ~OPOST;
        t->c_lflag &= ~(ICANON | ISIG | IEXTEN);
    } else {
        t->c_iflag |= IXON | BRKINT;
        t->c_oflag |= OPOST;
        t->c_lflag |= ISIG;
        if (flags & Z_CBREAK) {
            t->c_lflag &= ~(ICANON | IEXTEN);
        } else {
            t->c_lflag |= ICANON | IEXTEN;
        }
        if (flags & Z_CRMOD) {
            t->c_iflag |= ICRNL;
            t->c_oflag |= ONLCR;
        } else {
            t->c_iflag &= ~ICRNL;
            t->c_oflag &= ~ONLCR;
        }
        t->c_oflag = flags_to_host(oflags + 5, 1,
                                   flags & Z_XTABS ? oflags[5].z : 0,
                                   t->c_oflag);
    }
    if (!(t->c_lflag & ICANON)) {
        t->c_cc[VMIN] = 1;
        t->c_cc[VTIME] = 0;
    }
    if (flags & Z_ECHO) {
        t->c_lflag |= ECHO;
    } else {
        t->c_lflag &= ~ECHO;
    }
    if (flags & Z_TANDEM) {
        t->c_iflag |= IXOFF;
    } else {
        t->c_iflag &= ~IXOFF;
    }
}

/* struct tchars: interrupt, quit, start, stop, end of file, break */
static const int tchars_cc[6] = { VINTR, VQUIT, VSTART, VSTOP, VEOF, VEOL };

/*
 * struct termio: four flag words, the line discipline, eight control
 * characters.  Without ICANON the end-of-file and end-of-line slots hold
 * the minimum count and the timeout.
 */
static void get_termio(const struct termios *t, uint8_t *p)
{
    static const int cc[4] = { VINTR, VQUIT, VERASE, VKILL };
    uint16_t cflag = flags_to_zeus(cflags, ARRAY_SIZE(cflags), t->c_cflag);
    bool canon = t->c_lflag & ICANON;

    cflag |= speed_to_zeus(cfgetospeed(t));
    switch (t->c_cflag & CSIZE) {
    case CS6:
        cflag |= 0000020;
        break;
    case CS7:
        cflag |= 0000040;
        break;
    case CS8:
        cflag |= 0000060;
        break;
    }
    stw_be_p(p, flags_to_zeus(iflags, ARRAY_SIZE(iflags), t->c_iflag));
    stw_be_p(p + 2, flags_to_zeus(oflags, ARRAY_SIZE(oflags), t->c_oflag));
    stw_be_p(p + 4, cflag);
    stw_be_p(p + 6, flags_to_zeus(lflags, ARRAY_SIZE(lflags), t->c_lflag));
    p[8] = 0;
    memset(p + 9, 0, Z_NCC);
    for (int i = 0; i < 4; i++) {
        p[9 + i] = cc_to_zeus(t->c_cc[cc[i]]);
    }
    p[9 + Z_VEOF] = canon ? cc_to_zeus(t->c_cc[VEOF]) : t->c_cc[VMIN];
    p[9 + Z_VEOL] = canon ? cc_to_zeus(t->c_cc[VEOL]) : t->c_cc[VTIME];
}

static void set_termio(struct termios *t, const uint8_t *p)
{
    static const int cc[4] = { VINTR, VQUIT, VERASE, VKILL };
    static const tcflag_t sizes[4] = { CS5, CS6, CS7, CS8 };
    uint16_t cflag = lduw_be_p(p + 4);

    t->c_iflag = flags_to_host(iflags, ARRAY_SIZE(iflags), lduw_be_p(p),
                               t->c_iflag);
    t->c_oflag = flags_to_host(oflags, ARRAY_SIZE(oflags), lduw_be_p(p + 2),
                               t->c_oflag);
    t->c_cflag = flags_to_host(cflags, ARRAY_SIZE(cflags), cflag,
                               t->c_cflag);
    t->c_cflag = (t->c_cflag & ~CSIZE) | sizes[(cflag & Z_CSIZE) >> 4];
    t->c_lflag = flags_to_host(lflags, ARRAY_SIZE(lflags), lduw_be_p(p + 6),
                               t->c_lflag);
    set_speeds(t, cflag & Z_CBAUD, cflag & Z_CBAUD);
    for (int i = 0; i < 4; i++) {
        t->c_cc[cc[i]] = cc_to_host(p[9 + i]);
    }
    if (t->c_lflag & ICANON) {
        t->c_cc[VEOF] = cc_to_host(p[9 + Z_VEOF]);
        t->c_cc[VEOL] = cc_to_host(p[9 + Z_VEOL]);
    } else {
        t->c_cc[VMIN] = p[9 + Z_VEOF];
        t->c_cc[VTIME] = p[9 + Z_VEOL];
    }
}

/*
 * ioctl(fd, request, arg).  Returns 0 or a ZEUS error number.  arg is a
 * data pointer, or for a few requests a number.
 */
int zeus_ioctl(CPUZ8000State *env, int fd, uint32_t req, uint32_t arg)
{
    struct termios tio;
    uint32_t len = 0;
    uint8_t *p = NULL;
    int how = TCSANOW;

    switch (req) {
    case Z_FIOCLEX:
    case Z_FIONCLEX:
        return fcntl(fd, F_SETFD, req == Z_FIOCLEX ? FD_CLOEXEC : 0) < 0 ?
               Z_EBADF : 0;
    case Z_TIOCGETP:
    case Z_TIOCSETP:
    case Z_TIOCSETN:
    case Z_TIOCGETC:
    case Z_TIOCSETC:
        len = 6;
        break;
    case Z_TCGETA:
    case Z_TCSETA:
    case Z_TCSETAW:
    case Z_TCSETAF:
        len = 9 + Z_NCC;
        break;
    }

    if (tcgetattr(fd, &tio) < 0) {
        return errno == EBADF ? Z_EBADF : Z_ENOTTY;
    }
    if (len) {
        bool get = req == Z_TIOCGETP || req == Z_TIOCGETC ||
                   req == Z_TCGETA;

        p = zeus_data_ptr(env, arg, len, get);
        if (!p) {
            return Z_EFAULT;
        }
    }

    switch (req) {
    case Z_TIOCGETP:
        return get_sgttyb(&tio, p);
    case Z_TIOCSETP:
        /* waits for output and discards unread input */
        how = TCSAFLUSH;
        /* fall through */
    case Z_TIOCSETN:
        set_sgttyb(&tio, p);
        break;
    case Z_TIOCGETC:
        for (int i = 0; i < 6; i++) {
            p[i] = cc_to_zeus(tio.c_cc[tchars_cc[i]]);
        }
        return 0;
    case Z_TIOCSETC:
        for (int i = 0; i < 6; i++) {
            tio.c_cc[tchars_cc[i]] = cc_to_host(p[i]);
        }
        break;
    case Z_TCGETA:
        get_termio(&tio, p);
        return 0;
    case Z_TCSETAF:
        how = TCSAFLUSH;
        set_termio(&tio, p);
        break;
    case Z_TCSETAW:
        how = TCSADRAIN;
        /* fall through */
    case Z_TCSETA:
        set_termio(&tio, p);
        break;
    case Z_TCSBRK:
        /* wait for output; send a break unless the argument says not to */
        tcdrain(fd);
        if ((arg & 0xffff) == 0) {
            tcsendbreak(fd, 0);
        }
        return 0;
    case Z_TCXONC:
        tcflow(fd, (arg & 0xffff) ? TCOON : TCOOFF);
        return 0;
    case Z_TCFLSH:
        tcflush(fd, (arg & 0xffff) == 0 ? TCIFLUSH :
                    (arg & 0xffff) == 1 ? TCOFLUSH : TCIOFLUSH);
        return 0;
    case Z_TIOCFLUSH:
        tcflush(fd, TCIOFLUSH);
        return 0;
    case Z_TIOCHPCL:
        tio.c_cflag |= HUPCL;
        break;
    case Z_TIOCEXCL:
    case Z_TCXCLUSE:
        ioctl(fd, TIOCEXCL);
        return 0;
    case Z_TIOCNXCL:
    case Z_TCNXCLUSE:
        ioctl(fd, TIOCNXCL);
        return 0;
    default:
        return Z_EINVAL;
    }
    return tcsetattr(fd, how, &tio) < 0 ? Z_EINVAL : 0;
}
