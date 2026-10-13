/*
 * ZEUS user-mode emulation: guest memory
 *
 * A ZEUS process has a small, fixed address space, so the whole guest
 * range is reserved once and the spaces a program uses are opened in it.
 * There is no guest mmap.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu.h"
#include "exec/mmap-lock.h"
#include "exec/page-protection.h"
#include "user/guest-base.h"
#include "user/mmap.h"
#include <sys/mman.h>

unsigned long reserved_va;
unsigned long guest_addr_max;
abi_ulong mmap_next_start;

static pthread_mutex_t mmap_mutex = PTHREAD_MUTEX_INITIALIZER;
static __thread int mmap_lock_count;

void mmap_lock(void)
{
    if (mmap_lock_count++ == 0) {
        pthread_mutex_lock(&mmap_mutex);
    }
}

void mmap_unlock(void)
{
    assert(mmap_lock_count > 0);
    if (--mmap_lock_count == 0) {
        pthread_mutex_unlock(&mmap_mutex);
    }
}

bool have_mmap_lock(void)
{
    return mmap_lock_count > 0;
}

void mmap_fork_start(void)
{
    if (mmap_lock_count) {
        abort();
    }
    pthread_mutex_lock(&mmap_mutex);
}

void mmap_fork_end(int child)
{
    if (child) {
        pthread_mutex_init(&mmap_mutex, NULL);
    } else {
        pthread_mutex_unlock(&mmap_mutex);
    }
}

/* Reserve the guest address range and fix guest_base. */
void zeus_memory_init(void)
{
    size_t size = (size_t)1 << TARGET_VIRT_ADDR_SPACE_BITS;
    void *p = mmap(NULL, size, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);

    if (p == MAP_FAILED) {
        error_report("cannot reserve guest address space: %s",
                     strerror(errno));
        exit(EXIT_FAILURE);
    }
    guest_base = (uintptr_t)p;
    have_guest_base = true;
    reserved_va = size - 1;
    guest_addr_max = reserved_va;
}

/* Open one zero-filled 64K space at base, replacing what was there. */
void zeus_map_space(uint32_t base)
{
    void *p = mmap(g2h_untagged(base), ZEUS_SPACE_SIZE,
                   PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);

    if (p == MAP_FAILED) {
        error_report("cannot map guest memory: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    mmap_lock();
    page_set_flags(base, base + ZEUS_SPACE_SIZE - 1,
                   PAGE_VALID | PAGE_READ | PAGE_WRITE | PAGE_EXEC |
                   PAGE_ANON, PAGE_VALID | PAGE_RWX | PAGE_ANON);
    mmap_unlock();
}

/*
 * Host pointer for a data-space buffer of a non-segmented program, or
 * NULL if it does not fit in the space.
 *
 * Pages holding translated code are write-protected on the host, and in a
 * program with one address space code and data share pages.  Before the
 * emulator itself stores into guest memory the pages are checked for
 * writing, which discards the translations and lifts the protection.
 */
void *zeus_data_ptr(CPUZ8000State *env, uint32_t addr, uint32_t len,
                    bool write)
{
    addr &= 0xffff;
    if (len > ZEUS_SPACE_SIZE - addr) {
        return NULL;
    }
    if (write && len &&
        !page_check_range(env->data_tag | addr, len, PAGE_WRITE)) {
        return NULL;
    }
    return g2h_untagged(env->data_tag | addr);
}

/* Host copy of a NUL-terminated data-space string; NULL if unterminated. */
char *zeus_data_string(CPUZ8000State *env, uint32_t addr)
{
    const char *p;
    size_t max;

    addr &= 0xffff;
    max = ZEUS_SPACE_SIZE - addr;
    p = g2h_untagged(env->data_tag | addr);
    if (!memchr(p, 0, max)) {
        return NULL;
    }
    return g_strdup(p);
}
