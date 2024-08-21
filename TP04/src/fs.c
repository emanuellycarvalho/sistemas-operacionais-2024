#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/file.h>

#include "fs.h"

#define LINK_MAX (sb->blksz - 32) / sizeof(uint64_t)
#define NAME_MAX sb->blksz - (8 * sizeof(uint64_t))

int fs_has_links(struct superblock *sb, uint64_t thisblk);

struct dir {
	uint64_t dirnode;   
	uint64_t nodeBlock; 
	char *nodeName;     
};

struct link {
	uint64_t inode; 
	int index;      
};

int get_file_size(const char *fname) {
	int sz;
	FILE *fd = fopen(fname, "r");
	fseek(fd, 0L, SEEK_END);
	sz = ftell(fd);
	rewind(fd);
	fclose(fd);
	return sz;
}

void fs_read_data(struct superblock *sb, uint64_t pos, void *data) {
    lseek(sb->fd, pos * sb->blksz, SEEK_SET);
    if (read(sb->fd, data, sb->blksz) != sb->blksz) {
        perror("Read failed");
        exit(EXIT_FAILURE);
    }
}

void fs_write_data(struct superblock *sb, uint64_t pos, void *data) {
    lseek(sb->fd, pos * sb->blksz, SEEK_SET);
    if (write(sb->fd, data, sb->blksz) != sb->blksz) {
        perror("Write failed");
        exit(EXIT_FAILURE);
    }
}


struct dir* fs_find_dir_info(struct superblock *sb, const char *dpath) {
	int pathlenght = 0;
	char *token;
	char *pathCopy = malloc(NAME_MAX);
	char *nodeName = malloc(NAME_MAX);
	struct dir *dir = malloc(sizeof *dir); 

	strcpy(pathCopy, dpath);

	token = strtok(pathCopy, "/");
	if(token == NULL) {
		dir->dirnode = 1;
		dir->nodeBlock = 1;
		dir->nodeName = "";
		return dir;
	}

	while(token != NULL) {
		strcpy(nodeName, token);
		pathlenght++;
		token = strtok(NULL, "/");
	} 

	strcpy(pathCopy, dpath);

	uint64_t dirnode, nodeBlock, j;
	struct inode *inode = malloc(sb->blksz);
	struct nodeinfo *auxnodeinfo = malloc(sb->blksz);
	struct inode *auxinode = malloc(sb->blksz);
	struct nodeinfo *nodeinfo = malloc(sb->blksz);

	dirnode = 1;

	fs_read_data(sb, dirnode, (void*) inode);
	fs_read_data(sb, inode->meta, (void*) nodeinfo);
	token = strtok(pathCopy, "/");

	j = 0;

	for(int i = 0; i < pathlenght; i++) {
		while(j < LINK_MAX) {
			nodeBlock = inode->links[j];
			if(nodeBlock != 0) {
				fs_read_data(sb, nodeBlock, (void*) auxinode);
				fs_read_data(sb, auxinode->meta, (void*) auxnodeinfo);

				if(!strcmp(auxnodeinfo->name, token)) {
					if(i + 1 < pathlenght) dirnode = nodeBlock;
					inode = auxinode;
					nodeinfo = auxnodeinfo;
					break;
				}	
			}

			j++;

			if(j == LINK_MAX) {
				if(inode->next != 0) { 
					j = 0;
					fs_read_data(sb, inode->next, (void*)inode);
				}
				else{ 
					if(i + 1 == pathlenght) {
						nodeBlock = -1; 
						break;
					}
					else { 
						free(dir);
						free(nodeName);
						free(pathCopy);
						free(inode);
						free(nodeinfo);
						errno = ENOENT;
						return NULL;
					}
				}
			}
		}
		j = 0;
		token = strtok(NULL, "/");
	}

	dir->dirnode = dirnode;
	dir->nodeBlock = nodeBlock;
	dir->nodeName = malloc(NAME_MAX);
	strcpy(dir->nodeName, nodeName);

	free(nodeName);
	free(pathCopy);
	free(inode);
	free(nodeinfo);

	return dir;
}


struct link* fs_find_link(struct superblock *sb, uint64_t inodeblk, uint64_t linkvalue) {
	int i = 0;
	uint64_t actualblk = inodeblk;
	struct inode *inode = malloc(sb->blksz);
	struct link *link = malloc(sizeof *link);

	fs_read_data(sb, inodeblk, (void*) inode);

	while(i < LINK_MAX) {
		if(inode->links[i] == linkvalue) {
			link->inode = actualblk;
			link->index = i;
			break;
		}

		i++;

		if(i == LINK_MAX) {
			if(inode->next == 0) {
				link->index = -1;
				link->inode = actualblk;
				break;
			}
			else{ 
				i = 0;
				actualblk = inode->next;
				fs_read_data(sb, inode->next, (void*) inode);
			}
		}
	}

	free(inode);

	return link;
}


uint64_t fs_create_child(struct superblock *sb, uint64_t thisblk, uint64_t parentblk) {
	uint64_t ret;
	struct inode *childnode = malloc(sb->blksz);
	struct inode *inode = malloc(sb->blksz);

	fs_read_data(sb, thisblk, (void*) inode);

	inode->next = fs_get_block(sb);

	childnode->mode = IMCHILD;
	childnode->parent = parentblk;
	childnode->meta = thisblk;
	childnode->next = 0;
	for(int i = 0; i < LINK_MAX; i++) {
		childnode->links[i] = 0;
	}

	fs_write_data(sb, thisblk, (void*) inode);
	fs_write_data(sb, inode->next, (void*) childnode);

	ret = inode->next;

	free(inode);
	free(childnode);

	return ret;
}

void fs_add_link(struct superblock *sb, uint64_t parentblk, int linkindex, uint64_t newlink) {
	uint64_t nodeinfoblk;
	struct inode *inode = malloc(sb->blksz);
	struct nodeinfo *nodeinfo = malloc(sb->blksz);

	fs_read_data(sb, parentblk, (void*) inode);
	nodeinfoblk = inode->meta;
	if(inode->mode == IMCHILD) {
		struct inode *parentnode = malloc(sb->blksz);
		fs_read_data(sb, inode->parent, parentnode);
		nodeinfoblk = parentnode->meta;
		free(parentnode);
	}
  	fs_read_data(sb, nodeinfoblk, (void*) nodeinfo);	

	inode->links[linkindex] = newlink;
	nodeinfo->size++;

	fs_write_data(sb, parentblk, (void*) inode);
	fs_write_data(sb, nodeinfoblk, (void*) nodeinfo);

	free(inode);
}

void fs_remove_link(struct superblock *sb, uint64_t parentblk, int linkindex) {
	uint64_t nodeinfoblk;
	struct inode *inode = malloc(sb->blksz);
	struct nodeinfo *nodeinfo = malloc(sb->blksz);

	fs_read_data(sb, parentblk, (void*) inode);
	nodeinfoblk = inode->meta;
	if(inode->mode == IMCHILD) {
		struct inode *parentnode = malloc(sb->blksz);
		fs_read_data(sb, inode->parent, (void*) parentnode);
		nodeinfoblk = parentnode->meta;
		free(parentnode);
	}
	fs_read_data(sb, nodeinfoblk, (void*) nodeinfo);

	inode->links[linkindex] = 0;
	nodeinfo->size--;

	
	if(inode->mode == IMCHILD && inode->next == 0 && !fs_has_links(sb, parentblk)) {
		fs_put_block(sb, parentblk);
		struct inode *previousnode = malloc(sb->blksz);
		fs_read_data(sb, inode->meta, (void*) previousnode);
		previousnode->next = 0;
		fs_write_data(sb, inode->meta, (void*) previousnode);
		free(previousnode);
	}
	else {
		fs_write_data(sb, parentblk, (void*) inode);
	}
	fs_write_data(sb, nodeinfoblk, (void*) nodeinfo);

	free(inode);
}


int fs_has_links(struct superblock *sb, uint64_t thisblk) {
	int ret;
	struct inode *inode = malloc(sb->blksz);

	fs_read_data(sb, thisblk, (void*) inode);

	for(int i = 0; i < LINK_MAX; i++) {
		ret = inode->links[i] ? 1 : 0;
	}

	free(inode);

	return ret;
}

struct superblock * fs_format(const char *fname, uint64_t blocksize) {
	if(blocksize < MIN_BLOCK_SIZE) {
		errno = EINVAL;
		return NULL;
	}

	struct superblock *sb = malloc(sizeof *sb);
	struct inode *rootnode = malloc(blocksize);
	struct nodeinfo *rootinfo = malloc(blocksize);
	struct freepage *freepage = malloc(blocksize);

	sb->magic = 0xdcc605f5;
	sb->blks = get_file_size(fname) / blocksize;
	sb->blksz = blocksize;
	sb->freeblks = sb->blks - 3;
	sb->freelist = 3;
	sb->root = 1;
	sb->fd = open(fname, O_RDWR, 0666);

	rootnode->mode = IMDIR;
	rootnode->parent = 1;
	rootnode->meta = 2;
	rootnode->next = 0;
	for(int i = 0; i < LINK_MAX; i++) {
		rootnode->links[i] = 0;
	}

	rootinfo->size = 0;
	strcpy(rootinfo->name, "/");

	if(flock(sb->fd, LOCK_EX | LOCK_NB) == -1){
		errno = EBUSY;
		return NULL;
	}

	fs_write_data(sb, 0, (void*) sb);
	fs_write_data(sb, 1, (void*) rootnode);
	fs_write_data(sb, 2, (void*) rootinfo);

	for(uint64_t i = 3; i < sb->blks; i++) {
		if(i + 1 == sb->blks) {
			freepage->next = 0;
		}
		else {
			freepage->next = i + 1;
		}

		freepage->count = 0;
		fs_write_data(sb, i, (void*) freepage);
	}

	free(rootnode);
	free(rootinfo);
	free(freepage);

	if(sb->blks < MIN_BLOCK_COUNT) {
		close(sb->fd);
		free(sb);
		errno = ENOSPC;
		return NULL;
	}

	return sb;
}

struct superblock * fs_open(const char *fname) {
	struct superblock *sb = malloc(sizeof *sb);
	int fd = open(fname, O_RDWR, 0666);

	if(flock(fd, LOCK_EX | LOCK_NB) == -1){
		errno = EBUSY;
		return NULL;
	}

	read(fd, sb, sizeof *sb);
	sb->fd = fd;

	if(sb->magic != 0xdcc605f5) {
		errno = EBADF;
		return NULL;
	}

	return sb;
}

int fs_close(struct superblock *sb) {
	if(sb->magic != 0xdcc605f5) {
		errno = EBADF;
		return -1;
	}

	flock(sb->fd, LOCK_UN);
	close(sb->fd);
	free(sb);

	return 0;
}

uint64_t fs_get_block(struct superblock *sb) {
	if(sb->freeblks == 0) {
		return 0;
	}

	if(sb->magic != 0xdcc605f5) {
		errno = EBADF;
		return (uint64_t) -1;
	}

	uint64_t ret;

	struct freepage *freepage = malloc(sb->blksz);

	fs_read_data(sb, sb->freelist, (void*) freepage);

	ret = sb->freelist;
	sb->freeblks--;
	sb->freelist = freepage->next;

	fs_write_data(sb, 0, (void*) sb);

	free(freepage);

	return ret;
}

int fs_put_block(struct superblock *sb, uint64_t block) {
	if(sb->magic != 0xdcc605f5) {
		errno = EBADF;
		return -1;
	}

	struct freepage *freepage = malloc(sb->blksz);

	freepage->next = sb->freelist;
	freepage->count = 0;

	sb->freeblks++;
	sb->freelist = block;

	fs_write_data(sb, block, (void*) freepage);
	fs_write_data(sb, 0, (void*) sb);

	free(freepage);

	return 0;
}

int fs_write_file(struct superblock *sb, const char *fname, char *buf, size_t cnt) {
	uint64_t datablks, extrainodes, neededblks, links;
	uint64_t fileblk, previousblk, linkblk;
	struct dir *dir;
	struct link *link;
	struct inode *inode = malloc(sb->blksz);
	struct inode *childnode = malloc(sb->blksz);
	struct nodeinfo *nodeinfo = malloc(sb->blksz);

	datablks = (cnt / sb->blksz) + ((cnt % sb->blksz) ? 1 : 0); 
	extrainodes = 0; 

	if(datablks > LINK_MAX) {
		extrainodes = (datablks / LINK_MAX) + (datablks % LINK_MAX ? 1 : 0);
	}

	dir = fs_find_dir_info(sb, fname);

	if(dir == NULL) { 
		free(dir);
		free(inode);
		free(childnode);
		free(nodeinfo);
		return -1;
	}

	if(dir->nodeBlock != -1) {
		fs_unlink(sb, fname);
	}

	link = fs_find_link(sb, dir->dirnode, 0);

	neededblks = datablks + 2 + extrainodes + (link->index == -1 ? 1 : 0);

	if(neededblks > sb->freeblks) {
		free(dir);
		free(link);
		free(inode);
		free(childnode);
		free(nodeinfo);
		errno = ENOSPC;
		return -1;
	}

	fileblk = fs_get_block(sb);

	if(link->index == -1) { 
		fs_add_link(sb, fs_create_child(sb, link->inode, dir->dirnode), 0, fileblk);
	}
	else {
		fs_add_link(sb, link->inode, link->index, fileblk);
	}

	inode->mode = IMREG;
	inode->parent = dir->dirnode;
	inode->meta = fs_get_block(sb);
	inode->next = 0;

	fs_write_data(sb, fileblk, (void*) inode);

	links = (datablks > LINK_MAX) ? LINK_MAX : datablks;
	for(int i = 0; i < LINK_MAX; i++) {
		if(i < links) {
			linkblk = fs_get_block(sb);
			fs_write_data(sb, linkblk, (void*) (buf + i * sb->blksz));
			inode->links[i] = linkblk;
		}
		else{
			inode->links[i] = 0;
		}
	}
	datablks -= links;

	previousblk = fileblk;
	for(int i = 0; i < extrainodes; i++) {
		previousblk = fs_create_child(sb, previousblk, fileblk);

		fs_read_data(sb, previousblk, (void*) childnode);

		links = (datablks > LINK_MAX) ? LINK_MAX : datablks;
		for(int j = 0; j < LINK_MAX; j++) {
			if(j < links) {
				linkblk = fs_get_block(sb);
				fs_write_data(sb, linkblk, (void*) (buf + i * j * sb->blksz));
				childnode->links[j] = linkblk;
			}
			else{
				childnode->links[j] = 0;
			}
		}
		fs_write_data(sb, previousblk, (void*) childnode);
		datablks -= links;
	}

	nodeinfo->size = cnt;
	strcpy(nodeinfo->name, dir->nodeName);

	fs_write_data(sb, fileblk, (void*) inode);
	fs_write_data(sb, inode->meta, (void*) nodeinfo);

	free(dir);
	free(link);
	free(inode);
	free(childnode);
	free(nodeinfo);

	return 0;
}

ssize_t fs_read_file(struct superblock *sb, const char *fname, char *buf, size_t bufsz) {
    size_t numblks;
    struct dir *dir;
    struct inode *inode = malloc(sb->blksz);
    struct nodeinfo *nodeinfo = malloc(sb->blksz);

    if (inode == NULL || nodeinfo == NULL) {
        perror("Malloc failed");
        return -1;
    }

    dir = fs_find_dir_info(sb, fname);

    if (dir == NULL || dir->nodeBlock == -1) {
        free(dir);
        free(inode);
        free(nodeinfo);
        errno = ENOENT;
        return -1;
    }

    fs_read_data(sb, dir->nodeBlock, (void*) inode);
    fs_read_data(sb, inode->meta, (void*) nodeinfo);

    if (inode->mode != IMREG) {
        free(dir);
        free(inode);
        free(nodeinfo);
        errno = EISDIR;
        return -1;
    }

    if (bufsz > nodeinfo->size) bufsz = nodeinfo->size;
    numblks = (bufsz / sb->blksz) + ((bufsz % sb->blksz) ? 1 : 0);

    for (int i = 0; i < numblks; i++) {
        uint64_t blk;
        if (i < LINK_MAX) {
            blk = inode->links[i];
        } else if (inode->next != 0) {
            fs_read_data(sb, inode->next, (void*) inode);
            blk = inode->links[i % LINK_MAX];
        } else {
            break;
        }
        fs_read_data(sb, blk, buf + i * sb->blksz);
    }

    free(dir);
    free(inode);
    free(nodeinfo);

    return bufsz;
}

int fs_unlink(struct superblock *sb, const char *fname) {
	int numblks, numlinks;
	uint64_t thisblk, nextblk;
	struct dir *dir;
	struct link *link;
	struct inode *inode = malloc(sb->blksz);
	struct nodeinfo *nodeinfo = malloc(sb->blksz);

	dir = fs_find_dir_info(sb, fname);

	if(dir->nodeBlock == -1) {
		free(dir);
		free(inode);
		free(nodeinfo);
		errno = ENOENT;
		return -1;
	}

	fs_read_data(sb, dir->nodeBlock, (void*) inode);
	fs_read_data(sb, inode->meta, (void*) nodeinfo);

	if(inode->mode != IMREG) {
		free(dir);
		free(inode);
		free(nodeinfo);
		errno = ENOENT;
		return -1;
	}
	
	numblks = (nodeinfo->size / sb->blksz) + ((nodeinfo->size % sb->blksz) ? 1 : 0);
	numlinks = (numblks > LINK_MAX) ? LINK_MAX : numblks;
	for(int i = 0; i < numlinks; i++) {
		fs_put_block(sb, inode->links[i]);
	}
	numblks -= numlinks;
	nextblk = inode->next;
	fs_put_block(sb, dir->nodeBlock);
	fs_put_block(sb, inode->meta);

	while(nextblk != 0) {
		fs_read_data(sb, nextblk, inode);
		thisblk = nextblk;
		nextblk = inode->next;

		numlinks = (numblks > LINK_MAX) ? LINK_MAX : numblks;
		for(int i = 0; i < numlinks; i++) {
			fs_put_block(sb, inode->links[i]);
		}
		numblks -= numlinks;

		fs_put_block(sb, thisblk);
		fs_put_block(sb, inode->meta);
	}

	
	link = fs_find_link(sb, dir->dirnode, dir->nodeBlock);

	fs_remove_link(sb, link->inode, link->index);

	free(dir);
	free(link);
	free(inode);
	free(nodeinfo);

	return 0;
}

int fs_mkdir(struct superblock *sb, const char *dname) {
	uint64_t dirblk;
	struct dir *dir;
	struct link *link;
	struct inode *inode = malloc(sb->blksz);
	struct nodeinfo *nodeinfo = malloc(sb->blksz);

	dir = fs_find_dir_info(sb, dname);

	if(dir == NULL) {
		free(dir);
		free(inode);
		free(nodeinfo);
		return -1;
	}

	if(dir->nodeBlock != -1) {
		free(dir);
		free(inode);
		free(nodeinfo);
		errno = EEXIST;
		return -1;
	}

	link = fs_find_link(sb, dir->dirnode, 0);

	if((sb->freeblks < (2 + (link->index == -1 ? 1 : 0)))) {
		free(dir);
		free(link);
		free(inode);
		free(nodeinfo);
		errno = ENOSPC;
		return -1;
	}

	dirblk = fs_get_block(sb);

	
	if(link->index == -1) {
		fs_add_link(sb, fs_create_child(sb, link->inode, dir->dirnode), 0, dirblk);
	}
	else {
		fs_add_link(sb, link->inode, link->index, dirblk);
	}

	inode->mode = IMDIR;
	inode->parent = dir->dirnode;
	inode->meta = fs_get_block(sb);
	inode->next = 0;
	for(int i = 0; i < LINK_MAX; i++) {
		inode->links[i] = 0;
	}

	nodeinfo->size = 0;
	strcpy(nodeinfo->name, dir->nodeName);

	fs_write_data(sb, dirblk, (void*) inode);
	fs_write_data(sb, inode->meta, (void*) nodeinfo);

	free(dir);
	free(link);
	free(inode);
	free(nodeinfo);

	return 0;
}

int fs_rmdir(struct superblock *sb, const char *dname) {
	struct dir *dir;
	struct link *link;
	struct inode *inode = malloc(sb->blksz);
	struct nodeinfo *nodeinfo = malloc(sb->blksz);

	dir = fs_find_dir_info(sb, dname);

	if(dir == NULL) {
		free(dir);
		free(inode);
		free(nodeinfo);
		return -1;
	}

	if(dir->nodeBlock == 1) { 
		free(dir);
		free(inode);
		free(nodeinfo);
		errno = EBUSY;
		return -1;
	}

	fs_read_data(sb, dir->nodeBlock, (void*) inode);
	fs_read_data(sb, inode->meta, (void*) nodeinfo);

	if(inode->mode != IMDIR) {
		free(dir);
		free(inode);
		free(nodeinfo);
		errno = ENOTDIR;
		return -1;
	}

	if(nodeinfo->size) {
		free(dir);
		free(inode);
		free(nodeinfo);
		errno = ENOTEMPTY;
		return -1;
	}	

	fs_put_block(sb, dir->nodeBlock);
	fs_put_block(sb, inode->meta);

	link = fs_find_link(sb, dir->dirnode, dir->nodeBlock);

	fs_remove_link(sb, link->inode, link->index);

	free(dir);
	free(link);
	free(inode);
	free(nodeinfo);

	return 0;
}

char * fs_list_dir(struct superblock *sb, const char *dname) {
	char *ret = malloc(NAME_MAX);
	uint64_t elements, size;
	struct dir *dir;
	struct inode *inode = malloc(sb->blksz);
	struct inode *auxinode = malloc(sb->blksz);
	struct nodeinfo *nodeinfo = malloc(sb->blksz);
	struct nodeinfo *auxnodeinfo = malloc(sb->blksz);

	strcpy(ret, "");
	dir = fs_find_dir_info(sb, dname);

	if(dir == NULL) {
		free(dir);
		free(inode);
		free(auxinode);
		free(nodeinfo);
		free(auxnodeinfo);
		return NULL;
	}

	fs_read_data(sb, dir->nodeBlock, (void*) inode);
	fs_read_data(sb, inode->meta, (void*) nodeinfo);

	if(inode->mode != IMDIR) {
		free(dir);
		free(inode);
		free(auxinode);
		free(nodeinfo);
		free(auxnodeinfo);
		errno = ENOTDIR;
		return NULL;
	}

	if(nodeinfo->size == 0) {
		free(dir);
		free(inode);
		free(auxinode);
		free(nodeinfo);
		free(auxnodeinfo);
		return ret;
	}

	elements = 0;
	size = nodeinfo->size;

	while(elements < size) {
		for(int i = 0; i < LINK_MAX; i++) {
			if(inode->links[i] != 0) {
				fs_read_data(sb, inode->links[i], (void*) auxinode);
				fs_read_data(sb, auxinode->meta, (void*) auxnodeinfo);

				strcat(ret, auxnodeinfo->name);
				if(auxinode->mode == IMDIR) strcat(ret, "/");

				elements++;

				if(elements < size) strcat(ret, " ");
			}
		}
		if(inode->next != 0) {
			fs_read_data(sb, inode->next, (void*) inode);
		}
		else {
			break;
		}
	}

	free(dir);
	free(inode);
	free(auxinode);
	free(nodeinfo);
	free(auxnodeinfo);

	return ret;
}