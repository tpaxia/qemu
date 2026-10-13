/*
 * ZEUS user-mode emulation: errno values used only inside QEMU
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef SPECIAL_ERRNO_H
#define SPECIAL_ERRNO_H

/*
 * Returned by the shared safe-syscall code when a host system call was
 * interrupted before it started and must be restarted.  Outside the range
 * of ZEUS error numbers.
 */
#define QEMU_ERESTARTSYS  255

#endif
