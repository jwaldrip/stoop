#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc < 3) return 2;
    const char *op = argv[1];
    if (!strcmp(op, "pipe-fd")) {
        int pipefds[2];
        if (pipe(pipefds)) return 3;
        char name[64];
        snprintf(name, sizeof(name), "%s/%d", argv[2], pipefds[0]);
        int reopened = open(name, O_RDONLY);
        if (reopened < 0) return 4;
        close(reopened);
        close(pipefds[0]);
        close(pipefds[1]);
        return 0;
    }
    if (!strcmp(op, "fchdir")) {
        int fd = open(argv[2], O_RDONLY | O_DIRECTORY);
        if (fd < 0 || fchdir(fd)) return 3;
        close(fd);
        fd = open("f", O_RDONLY);
        if (fd < 0) return 4;
        close(fd);
        return 0;
    }
    if (!strcmp(op, "tmp")) {
        int fd = open(argv[2], O_TMPFILE | O_WRONLY, 0600);
        if (fd < 0) return 3;
        if (write(fd, "x", 1) != 1) return 4;
        if (argc > 3) {
            char source[64];
            snprintf(source, sizeof(source), "/proc/self/fd/%d", fd);
            if (linkat(AT_FDCWD, source, AT_FDCWD, argv[3], AT_SYMLINK_FOLLOW)) return 5;
        }
        close(fd);
        return 0;
    }
    if (!strcmp(op, "exchange") && argc == 4)
        return syscall(SYS_renameat2, AT_FDCWD, argv[2], AT_FDCWD, argv[3], 2) != 0;
    if (!strcmp(op, "rename") && argc == 4)
        return rename(argv[2], argv[3]) != 0;
    if (!strcmp(op, "creat")) {
        int fd = creat(argv[2], 0600);
        if (fd < 0) return 3;
        close(fd);
        return 0;
    }
    if (!strcmp(op, "truncate")) return truncate(argv[2], 2) != 0;
    if (!strcmp(op, "fchmodat2")) return syscall(452, AT_FDCWD, argv[2], 0755, 0) != 0;
    if (!strcmp(op, "fchmod")) {
        int fd = open(argv[2], O_RDONLY);
        if (fd < 0) return 3;
        int result = fchmod(fd, 0755);
        close(fd);
        return result != 0;
    }
    if (!strcmp(op, "unlinkat-rmdir")) {
        return unlinkat(AT_FDCWD, argv[2], AT_REMOVEDIR) == 0 ? 3 : 0;
    }
    if (!strcmp(op, "deleted-dirfd")) {
        int fd = open(argv[2], O_DIRECTORY | O_RDONLY);
        if (fd < 0 || rmdir(argv[2])) return 3;
        int child = openat(fd, "file", O_CREAT | O_WRONLY, 0600);
        if (child >= 0) close(child);
        close(fd);
        return 0;
    }
    return 2;
}
