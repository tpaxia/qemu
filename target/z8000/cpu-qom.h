/*
 * Zilog Z8000 CPU QOM declarations
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TARGET_Z8000_CPU_QOM_H
#define TARGET_Z8000_CPU_QOM_H

#include "hw/core/cpu.h"

#define TYPE_Z8000_CPU "z8000-cpu"

OBJECT_DECLARE_CPU_TYPE(Z8000CPU, Z8000CPUClass, Z8000_CPU)

#define Z8000_CPU_TYPE_SUFFIX "-" TYPE_Z8000_CPU
#define Z8000_CPU_TYPE_NAME(name) (name Z8000_CPU_TYPE_SUFFIX)

#endif
