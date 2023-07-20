/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef vm_page_h
#define vm_page_h

typedef struct {
    u64 next;
    u64 prev;
} queue_head_t, queue_chain_t;

typedef struct {
    u32 next;
    u32 prev;
} vm_page_queue_head_t, vm_page_queue_chain_t;

#define vmp_pageq    vmp_q_un.vmp_q_pageq
#define vmp_snext    vmp_q_un.vmp_q_snext

struct vm_page {
    union {
        vm_page_queue_chain_t vmp_q_pageq;
        u64 vmp_q_snext;
    } vmp_q_un;
    vm_page_queue_chain_t vmp_listq;
    vm_page_queue_chain_t vmp_specialq;
    u64 vmp_offset;
    u32 vmp_object;
    u32
        vmp_wire_count:16,
        vmp_q_state:4,
        vmp_on_specialq:2,
        vmp_gobbled:1,
        vmp_laundry:1,
        vmp_no_cache:1,
        vmp_private:1,
        vmp_reference:1,
        vmp_lopage:1,
        vmp_realtime:1,
        vmp_unused_page_bits:3;
    u32 vmp_next_m;
    u32
        vmp_busy:1,
        vmp_wanted:1,
        vmp_tabled:1,
        vmp_hashed:1,
        vmp_fictitious:1,
        vmp_clustered:1,
        vmp_pmapped:1,
        vmp_xpmapped:1,
        vmp_wpmapped:1,
        vmp_free_when_done:1,
        vmp_absent:1,
        vmp_error:1,
        vmp_dirty:1,
        vmp_cleaning:1,
        vmp_precious:1,
        vmp_overwriting:1,
        vmp_restart:1,
        vmp_unusual:1,
        vmp_cs_validated:4,
        vmp_cs_tainted:4,
        vmp_cs_nx:4,
        vmp_reusable:1,
        vmp_written_by_kernel:1;
};

struct vm_page* vm_pages = 0;
struct vm_page* vm_page_array_beginning_addr = 0;
struct vm_page* vm_page_array_ending_addr = 0;
u32 vm_first_phys_ppnum = 0;

#define __WORDSIZE 64

#define TiB(x) ((0ull + (x)) << 40)
#define GiB(x) ((0ull + (x)) << 30)

#if TARGET_MACOS
#define VM_KERNEL_POINTER_SIGNIFICANT_BITS 41
#define VM_MIN_KERNEL_ADDRESS ((u64)(0ull - TiB(2)))
#else /* TARGET_MACOS */
#define VM_KERNEL_POINTER_SIGNIFICANT_BITS 38
#define VM_MIN_KERNEL_ADDRESS ((u64)(0ull - GiB(144)))
#endif /* TARGET_MACOS */

#define VM_MIN_KERNEL_AND_KEXT_ADDRESS VM_MIN_KERNEL_ADDRESS

#define VM_PAGE_PACKED_PTR_ALIGNMENT    64
#define VM_PAGE_PACKED_ALIGNED          __attribute__((aligned(VM_PAGE_PACKED_PTR_ALIGNMENT)))
#define VM_PAGE_PACKED_PTR_BITS         31
#define VM_PAGE_PACKED_PTR_SHIFT        6
#define VM_PAGE_PACKED_PTR_BASE         ((usize)(VM_MIN_KERNEL_AND_KEXT_ADDRESS))
#define VM_PAGE_PACKED_FROM_ARRAY       0x80000000

typedef struct vm_packing_params {
    u64 vmpp_base;
    u8 vmpp_bits;
    u8 vmpp_shift;
    bool vmpp_base_relative;
} vm_packing_params_t;

static inline u64 vm_unpack_pointer(u64 packed, vm_packing_params_t params)
{
    if (!params.vmpp_base_relative) {
        i64 addr = (i64)(packed);
        addr <<= __WORDSIZE - params.vmpp_bits;
        addr >>= __WORDSIZE - params.vmpp_bits - params.vmpp_shift;
        return (u64)(addr);
    }

    if (packed) {
        return (packed << params.vmpp_shift) + params.vmpp_base;
    }

    return (u64)(0);
}

#define VM_PACKING_IS_BASE_RELATIVE(ns) \
    (ns##_BITS + ns##_SHIFT <= VM_KERNEL_POINTER_SIGNIFICANT_BITS)

#define VM_PACKING_PARAMS(ns)                                     \
    (vm_packing_params_t) {                                       \
        .vmpp_base = ns##_BASE,                                   \
        .vmpp_bits = ns##_BITS,                                   \
        .vmpp_shift = ns##_SHIFT,                                 \
        .vmpp_base_relative = VM_PACKING_IS_BASE_RELATIVE(ns),    \
    }

#define VM_UNPACK_POINTER(packed, ns) \
    vm_unpack_pointer(packed, VM_PACKING_PARAMS(ns))

static inline u64 vm_page_unpack_ptr(u64 packed_page)
{
    if (packed_page >= VM_PAGE_PACKED_FROM_ARRAY) {
        packed_page &= ~VM_PAGE_PACKED_FROM_ARRAY;
        return (u64)(&vm_pages[packed_page]);
    }

    return VM_UNPACK_POINTER(packed_page, VM_PAGE_PACKED_PTR);
}

#define VM_PAGE_UNPACK_PTR(p)    (vm_page_unpack_ptr((u64)(p)))
#define VM_OBJECT_UNPACK(p)      ((u64)(VM_UNPACK_POINTER(p, VM_PAGE_PACKED_PTR)))
#define VM_PAGE_OBJECT(p)        (VM_OBJECT_UNPACK((p)->vmp_object))

static inline u32 VM_PAGE_GET_PHYS_PAGE(struct vm_page* p)
{
    assert((p >= vm_page_array_beginning_addr) && (p < vm_page_array_ending_addr));
    return (u32)((u64)(p - vm_page_array_beginning_addr) + vm_first_phys_ppnum);
}

void print_vm_page(struct kfd* kfd, struct vm_page* page, u64 page_kaddr)
{
    assert(vm_pages);
    assert(vm_page_array_beginning_addr);
    assert(vm_page_array_ending_addr);
    assert(vm_first_phys_ppnum);

    print_message("struct vm_page @ %016llx", page_kaddr);
    struct vm_page* p = (struct vm_page*)(page_kaddr);
    print_x32(VM_PAGE_GET_PHYS_PAGE(p));
    print_x64(VM_PAGE_OBJECT(page));
    print_x64(page->vmp_offset);
    print_u32(page->vmp_q_state);
    print_u32(page->vmp_on_specialq);
    print_bool(page->vmp_gobbled);
    print_bool(page->vmp_laundry);
    print_bool(page->vmp_no_cache);
    print_bool(page->vmp_private);
    print_bool(page->vmp_reference);
    print_bool(page->vmp_lopage);
    print_bool(page->vmp_realtime);
    print_bool(page->vmp_busy);
    print_bool(page->vmp_wanted);
    print_bool(page->vmp_tabled);
    print_bool(page->vmp_hashed);
    print_bool(page->vmp_fictitious);
    print_bool(page->vmp_clustered);
    print_bool(page->vmp_pmapped);
    print_bool(page->vmp_xpmapped);
    print_bool(page->vmp_wpmapped);
    print_bool(page->vmp_free_when_done);
    print_bool(page->vmp_absent);
    print_bool(page->vmp_error);
    print_bool(page->vmp_dirty);
    print_bool(page->vmp_cleaning);
    print_bool(page->vmp_precious);
    print_bool(page->vmp_overwriting);
    print_bool(page->vmp_restart);
    print_bool(page->vmp_unusual);
    print_bool(page->vmp_reusable);
    print_bool(page->vmp_written_by_kernel);
}

#endif /* vm_page_h */
