/*
 * ZEUS user-mode emulation: the filesystem as a ZEUS program sees it
 *
 * The program's files live in a host directory tree, the ZEUS root given
 * with -L.  This file turns guest paths into host paths and presents host
 * objects the way ZEUS would:
 *
 *  - paths are resolved lexically inside the root, so ".." cannot leave it;
 *  - ownership, modes, link counts, inode and device numbers come from the
 *    manifest written by tools/mksysroot.py (.zeus-manifest.tsv in the
 *    root) where it has an entry, because the host cannot represent them;
 *  - a directory can be opened and read as a file of 16-byte entries
 *    (16-bit inode number, 14-character name);
 *  - device nodes exist only in the manifest; a few are mapped to host
 *    devices.
 *
 * Changes a program makes to metadata are kept for the life of the process
 * only; the manifest file is not rewritten.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "qemu/bswap.h"
#include "qemu.h"
#include <dirent.h>
#include <sys/stat.h>

#define MANIFEST_NAME ".zeus-manifest.tsv"
#define ZEUS_DIRSIZ   14

typedef struct ManifestEntry {
    char type;              /* f, d, c, b, p */
    uint16_t mode;          /* permission bits */
    uint16_t uid, gid;
    uint16_t nlink;
    uint16_t rdev;
    uint16_t dev;           /* which ZEUS filesystem */
    uint16_t ino;
    uint32_t mtime;
} ManifestEntry;

#define MAX_FDS 256

typedef struct FdInfo {
    char *gpath;            /* canonical guest path, or NULL */
    bool is_dir;            /* a synthesized directory image */
    uint32_t dir_size;
} FdInfo;

static GHashTable *manifest;        /* guest path -> ManifestEntry */
static char *guest_cwd;             /* canonical guest cwd, NULL if outside */
static FdInfo fdtab[MAX_FDS];

/* ---- paths ---- */

/* Lexically normalize an absolute guest path; ".." stops at the root. */
static char *normalize(const char *path)
{
    g_auto(GStrv) parts = g_strsplit(path, "/", -1);
    g_autoptr(GPtrArray) out = g_ptr_array_new();
    GString *s = g_string_new(NULL);

    for (int i = 0; parts[i]; i++) {
        if (!parts[i][0] || !strcmp(parts[i], ".")) {
            continue;
        }
        if (!strcmp(parts[i], "..")) {
            if (out->len) {
                g_ptr_array_remove_index(out, out->len - 1);
            }
            continue;
        }
        g_ptr_array_add(out, parts[i]);
    }
    for (guint i = 0; i < out->len; i++) {
        g_string_append_c(s, '/');
        g_string_append(s, g_ptr_array_index(out, i));
    }
    if (!s->len) {
        g_string_append_c(s, '/');
    }
    return g_string_free(s, FALSE);
}

/*
 * Resolve a guest path.  Returns the host path; *canon receives the
 * canonical guest path, or NULL when the path is outside the ZEUS root
 * (no root given, or a relative path while the current directory is
 * outside it).
 */
char *zeus_resolve(const char *gpath, char **canon)
{
    g_autofree char *joined = NULL;

    *canon = NULL;
    if (!zeus_sysroot) {
        return g_strdup(gpath);
    }
    if (gpath[0] == '/') {
        *canon = normalize(gpath);
    } else if (guest_cwd) {
        joined = g_strconcat(guest_cwd, "/", gpath, NULL);
        *canon = normalize(joined);
    } else {
        return g_strdup(gpath[0] ? gpath : ".");
    }
    return g_strconcat(zeus_sysroot, *canon, NULL);
}

char *zeus_host_path(const char *guest_path)
{
    g_autofree char *canon = NULL;

    return zeus_resolve(guest_path, &canon);
}

/* ---- manifest ---- */

static ManifestEntry *manifest_get(const char *canon)
{
    return canon && manifest ? g_hash_table_lookup(manifest, canon) : NULL;
}

static void load_manifest(void)
{
    g_autofree char *file = g_strconcat(zeus_sysroot, "/" MANIFEST_NAME, NULL);
    g_autofree char *text = NULL;
    g_auto(GStrv) lines = NULL;

    manifest = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
    if (!g_file_get_contents(file, &text, NULL, NULL)) {
        return;
    }
    lines = g_strsplit(text, "\n", -1);
    for (int i = 1; lines[i]; i++) {
        g_auto(GStrv) f = g_strsplit(lines[i], "\t", -1);
        ManifestEntry *e;
        const char *colon;

        if (g_strv_length(f) < 10) {
            continue;
        }
        e = g_new0(ManifestEntry, 1);
        e->type = f[1][0];
        e->mode = strtoul(f[2], NULL, 8);
        e->uid = strtoul(f[3], NULL, 10);
        e->gid = strtoul(f[4], NULL, 10);
        e->nlink = strtoul(f[6], NULL, 10);
        if (strchr(f[7], ',')) {
            e->rdev = (strtoul(f[7], NULL, 10) << 8) |
                      strtoul(strchr(f[7], ',') + 1, NULL, 10);
        }
        e->mtime = strtoul(f[8], NULL, 10);
        /* inode key is "mountpoint:number"; one device per mount point */
        colon = strrchr(f[9], ':');
        e->ino = colon ? strtoul(colon + 1, NULL, 10) : 0;
        if (colon) {
            g_autofree char *mp = g_strndup(f[9], colon - f[9]);
            e->dev = strcmp(mp, "/") ? (g_str_hash(mp) % 250) + 2 : 1;
        }
        g_hash_table_replace(manifest, g_strdup(f[0]), e);
    }
}

void zeus_fs_init(void)
{
    g_autofree char *root = NULL;
    g_autofree char *cwd = NULL;

    if (!zeus_sysroot) {
        return;
    }
    load_manifest();
    root = realpath(zeus_sysroot, NULL);
    cwd = realpath(".", NULL);
    if (root && cwd && g_str_has_prefix(cwd, root) &&
        (cwd[strlen(root)] == '/' || cwd[strlen(root)] == '\0')) {
        guest_cwd = g_strdup(cwd[strlen(root)] ? cwd + strlen(root) : "/");
    }
}

/* ---- inode numbers and stat ---- */

/* 16-bit inode number for a host object without a manifest entry. */
static uint16_t host_ino(const struct stat *st)
{
    uint32_t h = (uint32_t)st->st_ino ^ (uint32_t)(st->st_ino >> 16);

    h &= 0xffff;
    return h < 3 ? h + 3 : h;       /* 0 is "free", 2 is a root directory */
}

static uint16_t mode_type(const ManifestEntry *e, const struct stat *st)
{
    if (e) {
        switch (e->type) {
        case 'd': return 0040000;
        case 'c': return 0020000;
        case 'b': return 0060000;
        case 'p': return 0010000;
        default:  return 0100000;
        }
    }
    if (S_ISDIR(st->st_mode)) {
        return 0040000;
    } else if (S_ISCHR(st->st_mode)) {
        return 0020000;
    } else if (S_ISBLK(st->st_mode)) {
        return 0060000;
    } else if (S_ISFIFO(st->st_mode)) {
        return 0010000;
    }
    return 0100000;
}

/*
 * Fill a ZEUS struct stat (30 bytes) for a guest object.  st is the host
 * stat result, or NULL for an object that exists only in the manifest.
 */
static void fill_stat(uint8_t *p, const ManifestEntry *e,
                      const struct stat *st, const FdInfo *fi)
{
    struct stat zero = { 0 };
    uint32_t size;

    if (!st) {
        st = &zero;
    }
    size = fi && fi->is_dir ? fi->dir_size : st->st_size;
    stw_be_p(p + 0, e ? e->dev : (st->st_dev & 0xff) | 0x100);
    stw_be_p(p + 2, e ? e->ino : host_ino(st));
    stw_be_p(p + 4, mode_type(e, st) | (e ? e->mode : st->st_mode & 07777));
    stw_be_p(p + 6, e ? e->nlink : st->st_nlink);
    /* without an entry the object belongs to whoever runs the program */
    stw_be_p(p + 8, e ? e->uid : ZEUS_UID);
    stw_be_p(p + 10, e ? e->gid : ZEUS_GID);
    stw_be_p(p + 12, e ? e->rdev : 0);
    stl_be_p(p + 14, e && e->type != 'f' && e->type != 'd' ? 0 : size);
    stl_be_p(p + 18, st->st_atime ? st->st_atime : (e ? e->mtime : 0));
    stl_be_p(p + 22, st->st_mtime ? st->st_mtime : (e ? e->mtime : 0));
    stl_be_p(p + 26, st->st_ctime ? st->st_ctime : (e ? e->mtime : 0));
}

static bool manifest_only(const ManifestEntry *e)
{
    return e && e->type != 'f' && e->type != 'd';
}

static bool hidden_name(const char *canon, const char *name)
{
    return !strcmp(canon, "/") && !strcmp(name, MANIFEST_NAME);
}

/* Call fn for each manifest-only object directly inside a directory. */
static int foreach_manifest_only(const char *canon,
                                 void (*fn)(void *opaque, const char *name,
                                            const ManifestEntry *e),
                                 void *opaque)
{
    g_autofree char *prefix = g_strconcat(strcmp(canon, "/") ? canon : "",
                                          "/", NULL);
    GHashTableIter it;
    gpointer key, val;
    int n = 0;

    if (!manifest) {
        return 0;
    }
    g_hash_table_iter_init(&it, manifest);
    while (g_hash_table_iter_next(&it, &key, &val)) {
        const char *path = key;

        if (manifest_only(val) && g_str_has_prefix(path, prefix) &&
            !strchr(path + strlen(prefix), '/')) {
            if (fn) {
                fn(opaque, path + strlen(prefix), val);
            }
            n++;
        }
    }
    return n;
}

/* Size ZEUS would report for a directory: sixteen bytes per entry. */
static uint32_t directory_size(const char *canon, const char *host)
{
    uint32_t n = 2 + foreach_manifest_only(canon, NULL, NULL);
    struct dirent *de;
    DIR *d = opendir(host);

    if (!d) {
        return 0;
    }
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") && strcmp(de->d_name, "..") &&
            !hidden_name(canon, de->d_name)) {
            n++;
        }
    }
    closedir(d);
    return n * (2 + ZEUS_DIRSIZ);
}

/* stat by path; returns 0 or a negative host errno */
int zeus_fs_stat(const char *gpath, uint8_t *buf)
{
    g_autofree char *canon = NULL;
    g_autofree char *host = zeus_resolve(gpath, &canon);
    ManifestEntry *e = manifest_get(canon);
    struct stat st;

    if (manifest_only(e)) {
        fill_stat(buf, e, NULL, NULL);
        return 0;
    }
    if (stat(host, &st) < 0) {
        return -errno;
    }
    if (canon && S_ISDIR(st.st_mode)) {
        FdInfo dir = { .is_dir = true,
                       .dir_size = directory_size(canon, host) };

        fill_stat(buf, e, &st, &dir);
    } else {
        fill_stat(buf, e, &st, NULL);
    }
    return 0;
}

int zeus_fs_fstat(int fd, uint8_t *buf)
{
    FdInfo *fi = fd >= 0 && fd < MAX_FDS ? &fdtab[fd] : NULL;
    ManifestEntry *e = fi ? manifest_get(fi->gpath) : NULL;
    struct stat st;

    if (fi && fi->is_dir) {
        g_autofree char *canon = NULL;
        g_autofree char *host = zeus_resolve(fi->gpath, &canon);

        if (stat(host, &st) < 0) {
            return -errno;
        }
    } else if (fstat(fd, &st) < 0) {
        return -errno;
    }
    if (manifest_only(e)) {
        fill_stat(buf, e, NULL, NULL);
    } else {
        fill_stat(buf, e, &st, fi);
    }
    return 0;
}

/* ---- directories ---- */

static uint16_t path_ino(const char *canon)
{
    g_autofree char *host = g_strconcat(zeus_sysroot ? zeus_sysroot : "",
                                        canon, NULL);
    ManifestEntry *e = manifest_get(canon);
    struct stat st;

    if (e) {
        return e->ino;
    }
    if (lstat(host, &st) < 0) {
        return 3;
    }
    return host_ino(&st);
}

static void add_dirent(GByteArray *out, uint16_t ino, const char *name)
{
    uint8_t ent[2 + ZEUS_DIRSIZ] = { 0 };

    stw_be_p(ent, ino);
    /* names longer than a ZEUS directory entry are cut, as ZEUS would */
    memcpy(ent + 2, name, strnlen(name, ZEUS_DIRSIZ));
    g_byte_array_append(out, ent, sizeof(ent));
}

static void add_manifest_dirent(void *opaque, const char *name,
                                const ManifestEntry *e)
{
    add_dirent(opaque, e->ino, name);
}

/*
 * Build the image of a directory as ZEUS stores it and return a host
 * descriptor positioned at its start, or a negative host errno.
 */
static int open_directory(const char *canon, const char *host, FdInfo *info)
{
    g_autoptr(GByteArray) image = g_byte_array_new();
    g_autofree char *parent = g_path_get_dirname(canon);
    char tmpl[] = "/tmp/zeus-dir-XXXXXX";
    struct dirent *de;
    DIR *d;
    int fd;

    d = opendir(host);
    if (!d) {
        return -errno;
    }
    add_dirent(image, path_ino(canon), ".");
    add_dirent(image, path_ino(parent), "..");
    while ((de = readdir(d)) != NULL) {
        g_autofree char *child = NULL;

        if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..") ||
            hidden_name(canon, de->d_name)) {
            continue;
        }
        child = g_strconcat(strcmp(canon, "/") ? canon : "", "/",
                            de->d_name, NULL);
        add_dirent(image, path_ino(child), de->d_name);
    }
    closedir(d);

    /* objects that exist only in the manifest (device nodes) */
    foreach_manifest_only(canon, add_manifest_dirent, image);

    fd = mkstemp(tmpl);
    if (fd < 0) {
        return -errno;
    }
    unlink(tmpl);
    if (write(fd, image->data, image->len) != image->len ||
        lseek(fd, 0, SEEK_SET) < 0) {
        int e = errno;

        close(fd);
        return -e;
    }
    info->is_dir = true;
    info->dir_size = image->len;
    return fd;
}

/* ---- descriptors ---- */

static void fd_note(int fd, const char *canon, const FdInfo *info)
{
    if (fd < 0 || fd >= MAX_FDS) {
        return;
    }
    g_free(fdtab[fd].gpath);
    fdtab[fd] = info ? *info : (FdInfo){ 0 };
    fdtab[fd].gpath = g_strdup(canon);
}

void zeus_fs_close(int fd)
{
    fd_note(fd, NULL, NULL);
}

void zeus_fs_dup(int oldfd, int newfd)
{
    if (oldfd >= 0 && oldfd < MAX_FDS) {
        FdInfo info = fdtab[oldfd];

        fd_note(newfd, info.gpath, &info);
    }
}

/*
 * open: flags are host open flags.  Returns a descriptor or a negative
 * host errno.
 */
int zeus_fs_open(const char *gpath, int flags, int mode)
{
    g_autofree char *canon = NULL;
    g_autofree char *host = zeus_resolve(gpath, &canon);
    ManifestEntry *e = manifest_get(canon);
    FdInfo info = { 0 };
    struct stat st;
    int fd;

    if (manifest_only(e)) {
        /* device nodes: the few that have a host equivalent */
        if (!strcmp(canon, "/dev/null")) {
            fd = open("/dev/null", flags & ~(O_CREAT | O_TRUNC | O_EXCL));
        } else if (!strcmp(canon, "/dev/tty") ||
                   !strcmp(canon, "/dev/console")) {
            fd = open("/dev/tty", flags & ~(O_CREAT | O_TRUNC | O_EXCL));
        } else {
            return -ENXIO;
        }
    } else if (canon && stat(host, &st) == 0 && S_ISDIR(st.st_mode)) {
        if ((flags & O_ACCMODE) != O_RDONLY) {
            return -EISDIR;
        }
        fd = open_directory(canon, host, &info);
        if (fd < 0) {
            return fd;
        }
    } else {
        fd = open(host, flags, mode);
    }
    if (fd < 0) {
        return -errno;
    }
    fd_note(fd, canon, &info);
    return fd;
}

/* ---- calls that change the tree ---- */

int zeus_fs_chdir(const char *gpath)
{
    g_autofree char *canon = NULL;
    g_autofree char *host = zeus_resolve(gpath, &canon);

    if (chdir(host) < 0) {
        return -errno;
    }
    g_free(guest_cwd);
    guest_cwd = g_steal_pointer(&canon);
    return 0;
}

int zeus_fs_unlink(const char *gpath)
{
    g_autofree char *canon = NULL;
    g_autofree char *host = zeus_resolve(gpath, &canon);
    ManifestEntry *e = manifest_get(canon);

    if (manifest_only(e)) {
        g_hash_table_remove(manifest, canon);
        return 0;
    }
    if (unlink(host) < 0) {
        return -errno;
    }
    if (e) {
        g_hash_table_remove(manifest, canon);
    }
    return 0;
}

int zeus_fs_link(const char *gold, const char *gnew)
{
    g_autofree char *cold = NULL, *cnew = NULL;
    g_autofree char *hold = zeus_resolve(gold, &cold);
    g_autofree char *hnew = zeus_resolve(gnew, &cnew);
    ManifestEntry *e = manifest_get(cold);

    if (manifest_only(e)) {
        return -EPERM;
    }
    if (link(hold, hnew) < 0) {
        return -errno;
    }
    if (e && cnew) {
        e->nlink++;
        g_hash_table_replace(manifest, g_strdup(cnew),
                             g_memdup2(e, sizeof(*e)));
    }
    return 0;
}

int zeus_fs_chmod(const char *gpath, int mode)
{
    g_autofree char *canon = NULL;
    g_autofree char *host = zeus_resolve(gpath, &canon);
    ManifestEntry *e = manifest_get(canon);
    struct stat st;

    if (e) {
        e->mode = mode & 07777;
        return 0;
    }
    if (stat(host, &st) < 0) {
        return -errno;
    }
    return chmod(host, mode & 07777) < 0 ? -errno : 0;
}

int zeus_fs_chown(const char *gpath, int uid, int gid)
{
    g_autofree char *canon = NULL;
    g_autofree char *host = zeus_resolve(gpath, &canon);
    ManifestEntry *e = manifest_get(canon);
    struct stat st;

    if (e) {
        e->uid = uid;
        e->gid = gid;
        return 0;
    }
    /* host ownership cannot follow ZEUS ids; accept if the object exists */
    return stat(host, &st) < 0 ? -errno : 0;
}

/* access: the program runs as the ZEUS super-user */
int zeus_fs_access(const char *gpath, int amode)
{
    g_autofree char *canon = NULL;
    g_autofree char *host = zeus_resolve(gpath, &canon);
    ManifestEntry *e = manifest_get(canon);
    struct stat st;

    if (!manifest_only(e) && stat(host, &st) < 0) {
        return -errno;
    }
    if (amode & 1) {
        uint32_t mode = e ? e->mode : st.st_mode;
        bool dir = e ? e->type == 'd' : S_ISDIR(st.st_mode);

        if (!dir && !(mode & 0111)) {
            return -EACCES;
        }
    }
    return 0;
}
