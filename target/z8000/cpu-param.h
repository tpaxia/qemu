/*
 * Zilog Z8000 CPU parameters
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef Z8000_CPU_PARAM_H
#define Z8000_CPU_PARAM_H

#ifdef CONFIG_USER_ONLY
/* user-mode protections are applied in host pages */
#define TARGET_PAGE_BITS 12
#else
#define TARGET_PAGE_BITS 10
#endif
/*
 * 7-bit segment number and 16-bit offset, bit 23 for the PC's segment-word
 * bit 15, bit 24 for the data-space tag of split I&D programs.
 */
#define TARGET_VIRT_ADDR_SPACE_BITS 25

#endif
