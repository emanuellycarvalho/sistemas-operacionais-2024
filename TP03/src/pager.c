#include "pager.h"
#include "mmu.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <pthread.h>

typedef struct PageInfo {
    void *vaddr;
    int frame;
    int disk_block;  // Adiciona informação sobre o bloco de disco
    struct PageInfo *next;
} PageInfo;

typedef struct ProcessInfo {
    pid_t pid;
    PageInfo *pages;
    int num_pages;
    struct ProcessInfo *next;
} ProcessInfo;

static ProcessInfo *process_list = NULL;
static int total_frames;
static int total_blocks;
static int *frame_table; // Array to keep track of frame usage
static int *block_table; // Array to keep track of disk block usage
static int clock_hand = 0;

static ProcessInfo *find_process(pid_t pid) {
    ProcessInfo *proc = process_list;
    while (proc && proc->pid != pid) {
        proc = proc->next;
    }
    return proc;
}

void pager_init(int nframes, int nblocks) {
    total_frames = nframes;
    total_blocks = nblocks;
    frame_table = malloc(sizeof(int) * nframes);
    block_table = malloc(sizeof(int) * nblocks);
    memset(frame_table, 0, sizeof(int) * nframes); // 0 means frame is free
    memset(block_table, 0, sizeof(int) * nblocks); // 0 means block is free
}

void pager_create(pid_t pid) {
    ProcessInfo *proc = malloc(sizeof(ProcessInfo));
    proc->pid = pid;
    proc->pages = NULL;
    proc->num_pages = 0;
    proc->next = process_list;
    process_list = proc;
}

void *pager_extend(pid_t pid) {
    ProcessInfo *proc = find_process(pid);
    if (!proc) return NULL;

    int max_pages_per_process = 8;

    if (proc->num_pages >= max_pages_per_process) {
        return NULL;
    }

    PageInfo *page = malloc(sizeof(PageInfo));
    if (!page) {
        return NULL;
    }

    if (proc->num_pages == 0) {
        page->vaddr = (void *)(UVM_BASEADDR);
    } else {
        page->vaddr = (void *)((intptr_t)proc->pages->vaddr + 0x1000);
    }

    page->frame = -1;
    page->disk_block = -1; // Inicializa o bloco de disco como não utilizado
    page->next = proc->pages;
    proc->pages = page;
    proc->num_pages++;

    return page->vaddr;
}

static pthread_mutex_t pager_mutex = PTHREAD_MUTEX_INITIALIZER;

void pager_fault(pid_t pid, void *addr) {
    pthread_mutex_lock(&pager_mutex);

    ProcessInfo *proc = find_process(pid);
    if (!proc) {
        pthread_mutex_unlock(&pager_mutex);
        return;
    }

    PageInfo *page = proc->pages;
    while (page && page->vaddr != addr) {
        page = page->next;
    }

    if (!page) {
        pthread_mutex_unlock(&pager_mutex);
        exit(EXIT_FAILURE);
    }

    if (page->frame == -1) {
        int free_frame = -1;

        // Procura o primeiro quadro livre
        for (int i = 0; i < total_frames; i++) {
            if (frame_table[i] == 0) {
                free_frame = i;
                break;
            }
        }

        if (free_frame == -1) {
            while (1) {
                if (clock_hand == total_frames) {
                    clock_hand = 0;
                }

                PageInfo *p = proc->pages;
                while (p) {
                    if (frame_table[clock_hand] == p->frame) {
                        if (p->disk_block == -1) {
                            // Encontra o primeiro bloco de disco livre
                            for (int i = 0; i < total_blocks; i++) {
                                if (block_table[i] == 0) {
                                    p->disk_block = i;
                                    block_table[i] = 1; // Marca o bloco como utilizado
                                    break;
                                }
                            }
                        }

                        // Escreve a página no disco
                        mmu_disk_write(p->frame, p->disk_block);
                        mmu_chprot(pid, p->vaddr, PROT_NONE);
                        mmu_nonresident(pid, p->vaddr);
                        frame_table[clock_hand] = 0; // Libera o quadro
                        free_frame = clock_hand;
                        clock_hand++;
                        break;
                    }
                    p = p->next;
                }
                if (free_frame != -1) {
                    break;
                }
                clock_hand++;
            }
        }

        // Inicializa o quadro de memória física se for novo
        mmu_zero_fill(free_frame);
        page->frame = free_frame;
        frame_table[free_frame] = 1;

        // Se a página estava no disco, carregue-a para a memória
        if (page->disk_block != -1) {
            mmu_disk_read(page->disk_block, free_frame);
            block_table[page->disk_block] = 0; // Libera o bloco de disco
            page->disk_block = -1; // Reseta o bloco de disco na estrutura
        }

        // Torna a página residente com permissões de leitura
        mmu_resident(pid, addr, free_frame, PROT_READ);
    } else {
        mmu_chprot(pid, addr, PROT_READ | PROT_WRITE);
    }

    pthread_mutex_unlock(&pager_mutex);
}

int pager_syslog(pid_t pid, void *addr, size_t len) {
    ProcessInfo *proc = find_process(pid);
    if (!proc) {
        errno = EINVAL;
        return -1;
    }

    char *buffer = malloc(len);
    if (!buffer) {
        errno = ENOMEM;
        return -1;
    }

    for (size_t i = 0; i < len; i++) {
        void *vaddr = (void *)((intptr_t)addr + i);
        PageInfo *page = proc->pages;
        while (page && page->vaddr != (void *)((intptr_t)vaddr & ~0xFFF)) {
            page = page->next;
        }

        if (!page) {
            free(buffer);
            errno = EINVAL;
            return -1;
        }

        if (page->frame == -1) {
            pager_fault(pid, page->vaddr);
        }

        buffer[i] = *(char *)vaddr;
    }

    for (size_t i = 0; i < len; i++) {
        printf("%02x", buffer[i]);
    }

    free(buffer);
    return 0;
}

void pager_destroy(pid_t pid) {
    ProcessInfo *prev = NULL;
    ProcessInfo *proc = process_list;

    while (proc && proc->pid != pid) {
        prev = proc;
        proc = proc->next;
    }

    if (!proc) return;

    if (prev) {
        prev->next = proc->next;
    } else {
        process_list = proc->next;
    }

    PageInfo *page = proc->pages;
    while (page) {
        PageInfo *next = page->next;
        free(page);
        page = next;
    }

    free(proc);
}
