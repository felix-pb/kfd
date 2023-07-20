/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef vm_map_h
#define vm_map_h

#include "../static_types/vm_map_copy.h"

struct vm_map {
    u64 hdr_links_prev;
    u64 hdr_links_next;
    u64 min_offset;
    u64 max_offset;
    u64 hdr_nentries;
    u64 hdr_nentries_u64;
    u64 hdr_rb_head_store_rbh_root;
    u64 pmap;
    u64 hint;
    u64 hole_hint;
    u64 holes_list;
    u64 object_size;
};

const struct vm_map vm_map_versions[] = {
    {
        .hdr_links_prev = 0x10,
        .hdr_links_next = 0x18,
        .min_offset = 0x20,
        .max_offset = 0x28,
        .hdr_nentries = 0x30,
        .hdr_nentries_u64 = 0x30,
        .hdr_rb_head_store_rbh_root = 0x38,
        .pmap = 0x40,
        .hint = 0x98,
        .hole_hint = 0xa0,
        .holes_list = 0xa8,
        .object_size = 0xc0,
    },
    {
        .hdr_links_prev = 0x10,
        .hdr_links_next = 0x18,
        .min_offset = 0x20,
        .max_offset = 0x28,
        .hdr_nentries = 0x30,
        .hdr_nentries_u64 = 0x30,
        .hdr_rb_head_store_rbh_root = 0x38,
        .pmap = 0x40,
        .hint = 0x98,
        .hole_hint = 0xa0,
        .holes_list = 0xa8,
        .object_size = 0xc0,
    },
    {
        .hdr_links_prev = 0x10,
        .hdr_links_next = 0x18,
        .min_offset = 0x20,
        .max_offset = 0x28,
        .hdr_nentries = 0x30,
        .hdr_nentries_u64 = 0x30,
        .hdr_rb_head_store_rbh_root = 0x38,
        .pmap = 0x40,
        .hint = 0x80,
        .hole_hint = 0x88,
        .holes_list = 0x90,
        .object_size = 0xa8,
    },
    {
        .hdr_links_prev = 0x10,
        .hdr_links_next = 0x18,
        .min_offset = 0x20,
        .max_offset = 0x28,
        .hdr_nentries = 0x30,
        .hdr_nentries_u64 = 0x30,
        .hdr_rb_head_store_rbh_root = 0x38,
        .pmap = 0x40,
        .hint = 0x80,
        .hole_hint = 0x88,
        .holes_list = 0x90,
        .object_size = 0xa8,
    },
};

typedef u64 vm_map_hdr_links_prev_t;
typedef u64 vm_map_hdr_links_next_t;
typedef u64 vm_map_min_offset_t;
typedef u64 vm_map_max_offset_t;
typedef i32 vm_map_hdr_nentries_t;
typedef u64 vm_map_hdr_nentries_u64_t;
typedef u64 vm_map_hdr_rb_head_store_rbh_root_t;
typedef u64 vm_map_pmap_t;
typedef u64 vm_map_hint_t;
typedef u64 vm_map_hole_hint_t;
typedef u64 vm_map_holes_list_t;

struct _vm_map {
    u64 lock[2];
    struct vm_map_header hdr;
    u64 pmap;
    u64 size;
    u64 size_limit;
    u64 data_limit;
    u64 user_wire_limit;
    u64 user_wire_size;
#if TARGET_MACOS
    u64 vmmap_high_start;
#else /* TARGET_MACOS */
    u64 user_range[4];
#endif /* TARGET_MACOS */
    union {
        u64 vmu1_highest_entry_end;
        u64 vmu1_lowest_unnestable_start;
    } vmu1;
    u64 hint;
    union {
        u64 vmmap_hole_hint;
        u64 vmmap_corpse_footprint;
    } vmmap_u_1;
    union {
        u64 _first_free;
        u64 _holes;
    } f_s;
    u32 map_refcnt;
    u32
        wait_for_space:1,
        wiring_required:1,
        no_zero_fill:1,
        mapped_in_other_pmaps:1,
        switch_protect:1,
        disable_vmentry_reuse:1,
        map_disallow_data_exec:1,
        holelistenabled:1,
        is_nested_map:1,
        map_disallow_new_exec:1,
        jit_entry_exists:1,
        has_corpse_footprint:1,
        terminated:1,
        is_alien:1,
        cs_enforcement:1,
        cs_debugged:1,
        reserved_regions:1,
        single_jit:1,
        never_faults:1,
        uses_user_ranges:1,
        pad:12;
    u32 timestamp;
};

void print_vm_map(struct kfd* kfd, struct _vm_map* map, u64 map_kaddr)
{
    print_message("struct _vm_map @ %016llx", map_kaddr);
    print_x64(map->hdr.links.prev);
    print_x64(map->hdr.links.next);
    print_x64(map->hdr.links.start);
    print_x64(map->hdr.links.end);
    print_i32(map->hdr.nentries);
    print_u16(map->hdr.page_shift);
    print_bool(map->hdr.entries_pageable);
    print_x64(map->hdr.rb_head_store.rbh_root);
    print_x64(map->pmap);
    print_x64(map->size);
    print_x64(map->size_limit);
    print_x64(map->data_limit);
    print_x64(map->user_wire_limit);
    print_x64(map->user_wire_size);
    print_x64(map->vmu1.vmu1_lowest_unnestable_start);
    print_x64(map->hint);
    print_x64(map->vmmap_u_1.vmmap_hole_hint);
    print_x64(map->f_s._holes);
    print_u32(map->map_refcnt);
    print_bool(map->wait_for_space);
    print_bool(map->wiring_required);
    print_bool(map->no_zero_fill);
    print_bool(map->mapped_in_other_pmaps);
    print_bool(map->switch_protect);
    print_bool(map->disable_vmentry_reuse);
    print_bool(map->map_disallow_data_exec);
    print_bool(map->holelistenabled);
    print_bool(map->is_nested_map);
    print_bool(map->map_disallow_new_exec);
    print_bool(map->jit_entry_exists);
    print_bool(map->has_corpse_footprint);
    print_bool(map->terminated);
    print_bool(map->is_alien);
    print_bool(map->cs_enforcement);
    print_bool(map->cs_debugged);
    print_bool(map->reserved_regions);
    print_bool(map->single_jit);
    print_bool(map->never_faults);
    print_bool(map->uses_user_ranges);
    print_u32(map->timestamp);
}

#endif /* vm_map_h */
