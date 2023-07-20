/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef vm_object_h
#define vm_object_h

#include "vm_page.h"

#define vo_size                   vo_un1.vou_size
#define vo_cache_pages_to_scan    vo_un1.vou_cache_pages_to_scan
#define vo_shadow_offset          vo_un2.vou_shadow_offset
#define vo_cache_ts               vo_un2.vou_cache_ts
#define vo_owner                  vo_un2.vou_owner

struct vm_object {
    vm_page_queue_head_t memq;
    u64 Lock[2];
    union {
        u64 vou_size;
        i32 vou_cache_pages_to_scan;
    } vo_un1;
    u64 memq_hint;
    i32 ref_count;
    u32 resident_page_count;
    u32 wired_page_count;
    u32 reusable_page_count;
    u64 copy;
    u64 shadow;
    u64 pager;
    union {
        u64 vou_shadow_offset;
        u64 vou_cache_ts;
        u64 vou_owner;
    } vo_un2;
    u64 paging_offset;
    u64 pager_control;
    i32 copy_strategy;
    u32
        paging_in_progress:16,
        __object1_unused_bits:16;
    u32 activity_in_progress;
    u32
        all_wanted:11,
        pager_created:1,
        pager_initialized:1,
        pager_ready:1,
        pager_trusted:1,
        can_persist:1,
        internal:1,
        private:1,
        pageout:1,
        alive:1,
        purgable:2,
        purgeable_only_by_kernel:1,
        purgeable_when_ripe:1,
        shadowed:1,
        true_share:1,
        terminating:1,
        named:1,
        shadow_severed:1,
        phys_contiguous:1,
        nophyscache:1,
        for_realtime:1;
    queue_chain_t cached_list;
    u64 last_alloc;
    u64 cow_hint;
    i32 sequential;
    u32 pages_created;
    u32 pages_used;
    u32
        wimg_bits:8,
        code_signed:1,
        transposed:1,
        mapping_in_progress:1,
        phantom_isssd:1,
        volatile_empty:1,
        volatile_fault:1,
        all_reusable:1,
        blocked_access:1,
        set_cache_attr:1,
        object_is_shared_cache:1,
        purgeable_queue_type:2,
        purgeable_queue_group:3,
        io_tracking:1,
        no_tag_update:1,
        eligible_for_secluded:1,
        can_grab_secluded:1,
        __unused_access_tracking:1,
        vo_ledger_tag:3,
        vo_no_footprint:1;
    u8 scan_collisions;
    u8 __object4_unused_bits[1];
    u16 wire_tag;
    u32 phantom_object_id;
    queue_head_t uplq;
    queue_chain_t objq;
    queue_chain_t task_objq;
};

void print_vm_object(struct kfd* kfd, struct vm_object* object, u64 object_kaddr)
{
    print_message("struct vm_object @ %016llx", object_kaddr);
    print_x64(object->vo_size);
    print_i32(object->ref_count);
    print_u32(object->resident_page_count);
    print_u32(object->wired_page_count);
    print_u32(object->reusable_page_count);
    print_x64(object->copy);
    print_x64(object->shadow);
    print_x64(object->pager);
    print_x64(object->vo_shadow_offset);
    print_x64(object->paging_offset);
    print_x64(object->pager_control);
    print_i32(object->copy_strategy);
    print_u32(object->paging_in_progress);
    print_u32(object->activity_in_progress);
    print_bool(object->can_persist);
    print_bool(object->internal);
    print_bool(object->pageout);
    print_i32(object->purgable);
    print_bool(object->shadowed);
    print_bool(object->true_share);
    print_bool(object->named);

    if (object->resident_page_count) {
        u64 page_kaddr = VM_PAGE_UNPACK_PTR(object->memq.next);
        struct vm_page page = {};
        while (page_kaddr != object_kaddr) {
            kread((u64)(kfd), page_kaddr, &page, sizeof(page));
            print_vm_page(kfd, &page, page_kaddr);
            page_kaddr = VM_PAGE_UNPACK_PTR(page.vmp_listq.next);
        }
    }
}

#endif /* vm_object_h */
