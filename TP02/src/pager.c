#include "pager.h"
#include "mmu.h"
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>

typedef struct PageInfo {
    void *vaddr;
    int frame;
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
    memset(frame_table, 0, sizeof(int) * nframes); // 0 means frame is free
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

    // Limite de alocação de páginas por processo
    int max_pages_per_process = 8; // Limite fixo de 8 páginas por processo

    // Verificar se o processo já atingiu o limite de páginas
    if (proc->num_pages >= max_pages_per_process) {
        return NULL;
    }

    // Criação da nova página
    PageInfo *page = malloc(sizeof(PageInfo));
    if (!page) {
        return NULL; // Falha na alocação de memória
    }

    // Calcula o endereço virtual da nova página
    if (proc->num_pages == 0) {
        page->vaddr = (void *)(UVM_BASEADDR);
    } else {
        page->vaddr = (void *)((intptr_t)proc->pages->vaddr + 0x1000);
    }

    page->frame = -1;  // Página ainda não alocada na memória
    page->next = proc->pages;
    proc->pages = page;
    proc->num_pages++;

    // Retorna o endereço virtual da nova página
    return page->vaddr;
}


void pager_fault(pid_t pid, void *addr) {
    ProcessInfo *proc = find_process(pid);
    if (!proc) return;

    PageInfo *page = proc->pages;
    while (page && page->vaddr != addr) {
        page = page->next;
    }

    if (!page) {
        exit(EXIT_FAILURE);
    }

    if (page->frame == -1) {
        int free_frame = -1;
        while (free_frame == -1) {
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
                            if (p->vaddr) {
                                mmu_nonresident(proc->pid, p->vaddr);
                                mmu_disk_write(p->frame, clock_hand);
                                frame_table[clock_hand] = 0;
                                free_frame = clock_hand;
                                clock_hand++;
                                break;
                            } else {
                                mmu_chprot(proc->pid, p->vaddr, PROT_NONE);
                                p->frame = -1;
                            }
                        }
                        p = p->next;
                    }
                    if (free_frame != -1) {
                        break;
                    }
                    clock_hand++;
                }
            }
        }

        mmu_zero_fill(free_frame);
        mmu_resident(pid, addr, free_frame, PROT_READ);
        page->frame = free_frame;
        frame_table[free_frame] = 1;
    } else {
        mmu_chprot(pid, addr, PROT_READ | PROT_WRITE);
    }
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
    printf("\n");

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
