#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>

// NOTE: This implementation is limited to the two-level page table structure.

// FIXME: implement a handler to catch virtual page fault exceptions.

/*
 * Linear address format (x86-64 4-level paging):
 * 63    48  47    39  38    30  29    21  20    12  11    0
 * -----------------------------------------------------------
 * | SignEx |  PML4  |   PDPT   |   PD   |   PT   |  OFFSET  |
 * -----------------------------------------------------------
 */

typedef uint32_t bit_field;
#define nullptr NULL

#define PAGE_SIZE 4096

#define PAGE_COUNT 2

static inline size_t page_pml4_index(uintptr_t virtual_address)
{
    return virtual_address >> 39;
}

static inline size_t page_pdpt_index(uintptr_t virtual_address)
{
    return (virtual_address >> 30) & 0x1FF;
}

static inline size_t page_pd_index(uintptr_t virtual_address)
{
    return (virtual_address >> 21) & 0x1FF;
}

static inline size_t page_pt_index(uintptr_t virtual_address)
{
    return (virtual_address >> 12) & 0x1FF;
}

static inline size_t page_offset(uintptr_t virtual_address)
{
    return virtual_address & 0xFFF;
}

typedef struct
{
    uint32_t present : 1;
    uint32_t dirty : 1;
    uint32_t rw : 1; // read/write
    uint32_t us : 1; // user/supervisor
    uint32_t : 12;
    uint64_t address : 48;
} page_entry __attribute__((aligned));

void *page_table[PAGE_COUNT];

// now we restrict ourself to use ownly limited amount of pages
static void *allocate_page(void)
{
    void *p = malloc(PAGE_SIZE);
    memset(p, 0, PAGE_SIZE);
    return p;
}

static inline void set_page_entry(page_entry *entry, uintptr_t pyhsical_address)
{
    // the lower 48 bits of the physical address
    entry->address = pyhsical_address;
    // set the present bit
    entry->present = 1;
}

static inline void *get_addr_from_entry(page_entry *entry)
{
    return (void *)(entry->address);
}

static void insert_page_into_address_space(page_entry *dir,
                                           uintptr_t virtual_address, uintptr_t physical_address)
{
    page_entry *next = dir;

    page_entry *pml4_entry = &next[page_pml4_index(virtual_address)];

    if (!pml4_entry->present)
    {
        void *page_frame = allocate_page();
        set_page_entry(pml4_entry, (uintptr_t)page_frame);
        next = page_frame;

        // printf("page_frame = %p\n", page_frame);
        // printf("pml4_entry->address = %p\n", (void *)pml4_entry->address);
        // printf("pml4_entry->present = %u\n", pml4_entry->present);
        // printf("\n");
    }
    else
    {
        next = get_addr_from_entry(pml4_entry);
    }

    page_entry *pdpt_entry = &next[page_pdpt_index(virtual_address)];

    if (!pdpt_entry->present)
    {
        void *page_frame = allocate_page();
        set_page_entry(pdpt_entry, (uintptr_t)page_frame);
        next = page_frame;

        // printf("page_frame = %p\n", page_frame);
        // printf("pml4_entry->address = %p\n", (void *)pml4_entry->address);
        // printf("pml4_entry->present = %u\n", pml4_entry->present);
        // printf("\n");
    }
    else
    {
        next = get_addr_from_entry(pdpt_entry);
    }

    page_entry *pd_entry = &next[page_pd_index(virtual_address)];

    if (!pd_entry->present)
    {
        void *page_frame = allocate_page();
        set_page_entry(pd_entry, (uintptr_t)page_frame);
        next = page_frame;

        // printf("page_frame = %p\n", page_frame);
        // printf("pml4_entry->address = %p\n", (void *)pml4_entry->address);
        // printf("pml4_entry->present = %u\n", pml4_entry->present);
        // printf("\n");
    }
    else
    {
        next = get_addr_from_entry(pd_entry);
    }

    page_entry *pt_entry = &next[page_pt_index(virtual_address)];
    // we've reach the last level of the page table structure, put the page into it
    set_page_entry(pt_entry, physical_address);
}

static void *get_page_from_address_space(page_entry *dir,
                                         uintptr_t virtual_address)
{
    page_entry *next = dir;

    page_entry *pml4_entry = &next[page_pml4_index(virtual_address)];

    if (!pml4_entry->present)
        return nullptr;

    next = get_addr_from_entry(pml4_entry);

    page_entry *pdpt_entry = &next[page_pdpt_index(virtual_address)];

    if (!pdpt_entry->present)
        return nullptr;

    next = get_addr_from_entry(pdpt_entry);

    page_entry *pd_entry = &next[page_pd_index(virtual_address)];

    if (!pd_entry->present)
        return nullptr;

    next = get_addr_from_entry(pd_entry);

    page_entry *pt_entry = &next[page_pt_index(virtual_address)];

    if (!pt_entry->present)
        return nullptr;

    next = get_addr_from_entry(pt_entry);

    return (void *)((char *)next + page_offset(virtual_address));
}

// uintptr_t create_virtual_page
int page_count = 0;

// allocate a virtual page, and map it to a physical page
uintptr_t allocate_virtual_page(page_entry *dir)
{
    uintptr_t virtual_address = 0x000000000000F000 + page_count * 4096;
    page_count++;

    void *page_frame = allocate_page();

    uintptr_t physical_address = (uintptr_t)page_frame;
    insert_page_into_address_space(dir, virtual_address, physical_address);
    return virtual_address;
}

int main(void)
{
    // basic assertions
    // assert(sizeof(page_entry) == 4);
    // if (sizeof(void *) != 4)
    // {
    //     printf("This program is intended to run on a 32-bits machine. "
    //            "If using GCC on a x86-64 machine, compile it with -m32.\n");
    //     return -1;
    // }

    // insert new page directory into the virtual control register 3.
    // root level table is forced to stay
    page_entry *cr3 = allocate_page();

    uintptr_t virtual_address_1 = allocate_virtual_page(cr3);
    char *physical_address_1 = get_page_from_address_space(cr3, virtual_address_1);

    for (int i = 0; i < PAGE_SIZE - 1; i++)
    {
        physical_address_1[i] = i % 10 + '0';
    }
    physical_address_1[PAGE_SIZE - 1] = '\0';

    puts(physical_address_1);
    // free(cr3);
    // free(page_frame);

    // printf("done!\n");

    return 0;
}