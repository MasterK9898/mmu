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

#define SWAP_FILE "swap_file"

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
    uint32_t present : 1; // 1 = present in memory, 0 = not present (in swap file or not allocated at all)
    uint32_t disk : 1;    // 1 = in swap file, 0 = in memory
    uint32_t rw : 1;      // read/write
    uint32_t us : 1;      // user/supervisor
    uint32_t : 12;        // reserved
    uint64_t address : 48;
} page_entry __attribute__((aligned));

// typedef struct {}

// the "ram"
void *page_table[PAGE_COUNT];

// use to trace back the virtual address from the physical address
uintptr_t reverse_map[PAGE_COUNT];

// the position of the next page to be allocated
size_t table_pos = 0;

// the position of the next page to be swapped out
size_t swap_pos = 0;

int swap_fd;

void *pair_address(page_entry *dir, uintptr_t virtual_address);

void init_page_table()
{
    for (int i = 0; i < PAGE_COUNT; i++)
    {
        void *p = malloc(PAGE_SIZE);
        memset(p, 0, PAGE_SIZE);
        page_table[i] = p;
    }

    swap_fd = open(SWAP_FILE, O_RDWR | O_CREAT, 0666);
}

// allocate page that is pinned in memory, used for page tables
static void *allocate_pinned_page()
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

static inline void swap_out_page_entry(page_entry *entry, uintptr_t pyhsical_address)
{
    uintptr_t swap_address = PAGE_SIZE * swap_pos++;
    // write the page to the swap file
    lseek(swap_fd, swap_address, SEEK_SET);
    write(swap_fd, (void *)pyhsical_address, PAGE_SIZE);

    // now the page is in the swap file
    entry->address = swap_address;
    // set the present bit
    entry->present = 0;
    entry->disk = 1;
}

static inline void swap_in_page_entry(page_entry *entry, uintptr_t pyhsical_address)
{
    uintptr_t swap_address = entry->address;
    // write the page to the swap file
    lseek(swap_fd, swap_address, SEEK_SET);
    read(swap_fd, (void *)pyhsical_address, PAGE_SIZE);
    // now the page is in the swap file
    entry->address = pyhsical_address;
    // set the present bit
    entry->present = 1;
    entry->disk = 0;
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

    // printf("pml4_index = %lu\n", page_pml4_index(virtual_address));

    // for simplicity, we never swap of page table pages

    if (!pml4_entry->present)
    {
        void *page_frame = allocate_pinned_page();
        set_page_entry(pml4_entry, (uintptr_t)page_frame);
        next = page_frame;

        // printf("page_frame = %p\n", page_frame);
        // printf("pml4_entry->address = %p\n", (void *)pml4_entry->address);
        // printf("pml4_entry->present = %u\n", pml4_entry->present);
        // printf("\n");
    }
    else
    {
        // printf("found pml4_entry\n");
        next = get_addr_from_entry(pml4_entry);
    }

    page_entry *pdpt_entry = &next[page_pdpt_index(virtual_address)];

    // printf("pdpt_index = %lu\n", page_pdpt_index(virtual_address));

    if (!pdpt_entry->present)
    {
        void *page_frame = allocate_pinned_page();
        set_page_entry(pdpt_entry, (uintptr_t)page_frame);
        next = page_frame;

        // printf("page_frame = %p\n", page_frame);
        // printf("pml4_entry->address = %p\n", (void *)pml4_entry->address);
        // printf("pml4_entry->present = %u\n", pml4_entry->present);
        // printf("\n");
    }
    else
    {
        // printf("found pdpt_entry\n");
        next = get_addr_from_entry(pdpt_entry);
    }

    page_entry *pd_entry = &next[page_pd_index(virtual_address)];

    // printf("pd_index = %lu\n", page_pd_index(virtual_address));

    if (!pd_entry->present)
    {
        void *page_frame = allocate_pinned_page();
        set_page_entry(pd_entry, (uintptr_t)page_frame);
        next = page_frame;

        // printf("page_frame = %p\n", page_frame);
        // printf("pml4_entry->address = %p\n", (void *)pml4_entry->address);
        // printf("pml4_entry->present = %u\n", pml4_entry->present);
        // printf("\n");
    }
    else
    {
        // printf("found pd_entry\n");
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
    {
        printf("pt_entry->address = %p\n", (void *)pt_entry->address);
        if (pt_entry->disk)
        {
            // the page is in the swap file

            // grab someone else's page
            void *physical_address = pair_address(dir, virtual_address);
            swap_in_page_entry(pt_entry, (uintptr_t)physical_address);
        }
        else
        {
            return nullptr;
        }
    }
    // return nullptr;

    next = get_addr_from_entry(pt_entry);

    return (void *)((char *)next + page_offset(virtual_address));
}

// swapping page out, will always write to the swap file
static void swap_page_from_address_space(page_entry *dir,
                                         uintptr_t virtual_address)
{
    // because all the page table pages are pinned in memory, we don't need to worry about them
    // we only need to swap out the last level page table
    page_entry *next = dir;

    page_entry *pml4_entry = &next[page_pml4_index(virtual_address)];

    // this should not happen
    if (!pml4_entry->present)
        return;

    next = get_addr_from_entry(pml4_entry);

    page_entry *pdpt_entry = &next[page_pdpt_index(virtual_address)];

    // this should not happen
    if (!pdpt_entry->present)
        return;

    next = get_addr_from_entry(pdpt_entry);

    page_entry *pd_entry = &next[page_pd_index(virtual_address)];

    // this should not happen
    if (!pd_entry->present)
        return;

    next = get_addr_from_entry(pd_entry);

    page_entry *pt_entry = &next[page_pt_index(virtual_address)];

    // this should not happen
    if (!pt_entry->present)
        return;

    // now next is the physical address of the page table
    next = get_addr_from_entry(pt_entry);

    swap_out_page_entry(pt_entry, (uintptr_t)next);
}

// get the physical address of a virtual page
void *pair_address(page_entry *dir, uintptr_t virtual_address)
{
    void *page_frame = page_table[table_pos];

    if (reverse_map[table_pos] != 0)
    {
        // we need to free the page
        uintptr_t victim_address = reverse_map[table_pos];
        swap_page_from_address_space(dir, victim_address);
        memset(page_frame, 0, PAGE_SIZE);
    }

    reverse_map[table_pos] = virtual_address;

    // next plz
    table_pos++;
    table_pos %= PAGE_COUNT;

    return page_frame;
}

// uintptr_t create_virtual_page
int page_count = 0;

// allocate a virtual page, and map it to a physical page
uintptr_t allocate_virtual_page(page_entry *dir)
{
    uintptr_t virtual_address = 0x000000000000F000 + page_count * 4096;
    page_count++;

    // void *page_frame = allocate_page();

    void *page_frame = pair_address(dir, virtual_address);

    uintptr_t physical_address = (uintptr_t)page_frame;
    insert_page_into_address_space(dir, virtual_address, physical_address);
    return virtual_address;
}

int main(void)
{
    init_page_table();
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
    page_entry *cr3 = allocate_pinned_page();

    uintptr_t virtual_address_1 = allocate_virtual_page(cr3);
    char *physical_address_1 = get_page_from_address_space(cr3, virtual_address_1);

    for (int i = 0; i < PAGE_SIZE - 1; i++)
    {
        physical_address_1[i] = i % 10 + '0';
    }
    physical_address_1[PAGE_SIZE - 1] = '\0';

    puts(physical_address_1);

    uintptr_t virtual_address_2 = allocate_virtual_page(cr3);

    uintptr_t virtual_address_3 = allocate_virtual_page(cr3);
    char *physical_address_3 = get_page_from_address_space(cr3, virtual_address_3);

    // uintptr_t virtual_address_4 = allocate_virtual_page(cr3);
    // char *physical_address_4 = get_page_from_address_space(cr3, virtual_address_4);
    puts(physical_address_3);

    physical_address_1 = get_page_from_address_space(cr3, virtual_address_1);

    puts(physical_address_1);
    // free(cr3);
    // free(page_frame);

    // printf("done!\n");

    return 0;
}