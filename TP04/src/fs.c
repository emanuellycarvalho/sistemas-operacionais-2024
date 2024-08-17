#include "fs.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

/* Helper functions */
static int read_block(int fd, uint64_t block_num, void *buf, uint64_t block_size) {
    if (lseek(fd, block_num * block_size, SEEK_SET) == (off_t)-1) {
        return -1;
    }
    return read(fd, buf, block_size) == (ssize_t)block_size ? 0 : -1;
}

static int write_block(int fd, uint64_t block_num, const void *buf, uint64_t block_size) {
    if (lseek(fd, block_num * block_size, SEEK_SET) == (off_t)-1) {
        return -1;
    }
    return write(fd, buf, block_size) == (ssize_t)block_size ? 0 : -1;
}

struct superblock *fs_format(const char *fname, uint64_t blocksize) {
    if (blocksize < MIN_BLOCK_SIZE) {
        errno = EINVAL;
        return NULL;
    }

    FILE *fp = fopen(fname, "r+");
    if (!fp) {
        return NULL;
    }

    fseek(fp, 0, SEEK_END);
    uint64_t file_size = ftell(fp);
    if (file_size < blocksize * MIN_BLOCK_COUNT) {
        errno = ENOSPC;
        fclose(fp);
        return NULL;
    }

    struct superblock *sb = malloc(sizeof(struct superblock));
    if (!sb) {
        fclose(fp);
        return NULL;
    }

    sb->magic = 0xdcc605f5;
    sb->blks = file_size / blocksize;
    sb->blksz = blocksize;
    sb->freeblks = sb->blks - 1;
    sb->freelist = 1;
    sb->root = 0;
    sb->fd = fileno(fp);

    struct freepage *fpage = calloc(1, blocksize);
    if (!fpage) {
        free(sb);
        fclose(fp);
        return NULL;
    }
    fpage->count = sb->freeblks;
    for (uint64_t i = 0; i < sb->freeblks; ++i) {
        fpage->links[i] = i + 1;
    }

    if (write_block(sb->fd, sb->freelist, fpage, blocksize) == -1) {
        free(fpage);
        free(sb);
        fclose(fp);
        return NULL;
    }

    struct inode root_inode = { .mode = IMDIR, .parent = 0, .meta = 0, .next = 0 };
    memset(root_inode.links, 0, blocksize - sizeof(struct inode));
    if (write_block(sb->fd, sb->root, &root_inode, blocksize) == -1) {
        free(fpage);
        free(sb);
        fclose(fp);
        return NULL;
    }

    free(fpage);
    fclose(fp);
    return sb;
}

struct superblock *fs_open(const char *fname) {
    FILE *fp = fopen(fname, "r+");
    if (!fp) {
        return NULL;
    }

    struct superblock *sb = malloc(sizeof(struct superblock));
    if (!sb) {
        fclose(fp);
        return NULL;
    }

    if (fread(sb, sizeof(struct superblock), 1, fp) != 1 || sb->magic != 0xdcc605f5) {
        free(sb);
        fclose(fp);
        errno = EBADF;
        return NULL;
    }

    sb->fd = fileno(fp);
    return sb;
}

int fs_close(struct superblock *sb) {
    if (!sb) {
        errno = EBADF;
        return -1;
    }

    if (close(sb->fd) == -1) {
        free(sb);
        return -1;
    }

    free(sb);
    return 0;
}

uint64_t fs_get_block(struct superblock *sb) {
    if (sb->freeblks == 0) {
        return 0;
    }

    struct freepage *fpage = malloc(sb->blksz);
    if (!fpage) {
        return (uint64_t)-1;
    }

    if (read_block(sb->fd, sb->freelist, fpage, sb->blksz) == -1) {
        free(fpage);
        return (uint64_t)-1;
    }

    uint64_t block = fpage->links[--fpage->count];
    if (fpage->count == 0) {
        sb->freelist = fpage->next;
    }

    if (write_block(sb->fd, sb->freelist, fpage, sb->blksz) == -1) {
        free(fpage);
        return (uint64_t)-1;
    }

    sb->freeblks--;
    free(fpage);
    return block;
}

int fs_put_block(struct superblock *sb, uint64_t block) {
    struct freepage *fpage = malloc(sb->blksz);
    if (!fpage) {
        return -1;
    }

    if (read_block(sb->fd, sb->freelist, fpage, sb->blksz) == -1) {
        free(fpage);
        return -1;
    }

    fpage->links[fpage->count++] = block;
    if (write_block(sb->fd, sb->freelist, fpage, sb->blksz) == -1) {
        free(fpage);
        return -1;
    }

    sb->freeblks++;
    free(fpage);
    return 0;
}

int fs_write_file(struct superblock *sb, const char *fname, char *buf, size_t cnt) {
    struct inode dir_inode;
    if (read_block(sb->fd, sb->root, &dir_inode, sb->blksz) == -1) {
        return -1;
    }

    for (size_t i = 0; i < MAX_LINKS; ++i) {
        if (dir_inode.links[i] != 0) {
            struct inode file_inode;
            if (read_block(sb->fd, dir_inode.links[i], &file_inode, sb->blksz) == -1) {
                return -1;
            }

            if (strcmp(file_inode.name, fname) == 0) {
                if (file_inode.mode != IMREG) {
                    errno = EISDIR;
                    return -1;
                }

                size_t remaining = cnt;
                char *buffer_ptr = buf;

                while (remaining > 0) {
                    size_t to_write = (remaining > sb->blksz) ? sb->blksz : remaining;

                    if (write_block(sb->fd, file_inode.links[0], buffer_ptr, sb->blksz) == -1) {
                        return -1;
                    }

                    buffer_ptr += to_write;
                    remaining -= to_write;
                }
                return 0;
            }
        }
    }

    errno = ENOENT;
    return -1;
}

ssize_t fs_read_file(struct superblock *sb, const char *fname, char *buf, size_t bufsz) {
    struct inode dir_inode;
    if (read_block(sb->fd, sb->root, &dir_inode, sb->blksz) == -1) {
        return -1;
    }

    for (size_t i = 0; i < MAX_LINKS; ++i) {
        if (dir_inode.links[i] != 0) {
            struct inode file_inode;
            if (read_block(sb->fd, dir_inode.links[i], &file_inode, sb->blksz) == -1) {
                return -1;
            }

            if (strcmp(file_inode.name, fname) == 0) {
                if (file_inode.mode != IMREG) {
                    errno = EISDIR;
                    return -1;
                }

                size_t to_read = (bufsz > sb->blksz) ? sb->blksz : bufsz;
                if (read_block(sb->fd, file_inode.links[0], buf, to_read) == -1) {
                    return -1;
                }

                return to_read;
            }
        }
    }

    errno = ENOENT;
    return -1;
}

int fs_unlink(struct superblock *sb, const char *fname) {
    struct inode dir_inode;
    if (read_block(sb->fd, sb->root, &dir_inode, sb->blksz) == -1) {
        return -1;
    }

    for (size_t i = 0; i < MAX_LINKS; ++i) {
        if (dir_inode.links[i] != 0) {
            struct inode file_inode;
            if (read_block(sb->fd, dir_inode.links[i], &file_inode, sb->blksz) == -1) {
                return -1;
            }

            if (strcmp(file_inode.name, fname) == 0) {
                if (file_inode.mode == IMDIR) {
                    errno = EISDIR;
                    return -1;
                }

                if (fs_put_block(sb, dir_inode.links[i]) == -1) {
                    return -1;
                }

                dir_inode.links[i] = 0;
                if (write_block(sb->fd, sb->root, &dir_inode, sb->blksz) == -1) {
                    return -1;
                }

                return 0;
            }
        }
    }

    errno = ENOENT;
    return -1;
}
