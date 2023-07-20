/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef pmap_h
#define pmap_h

struct pmap {
    u64 tte;
    u64 ttep;
    u64 min;
    u64 max;
    u64 pmap_pt_attr;
    u64 ledger;
    u64 rwlock[2];
    struct {
        u64 next;
        u64 prev;
    } pmaps;
    u64 tt_entry_free;
    u64 nested_pmap;
    u64 nested_region_addr;
    u64 nested_region_size;
    u64 nested_region_true_start;
    u64 nested_region_true_end;
    u64 nested_region_asid_bitmap;
    u32 nested_region_asid_bitmap_size;
    u64 reserved0;
    u64 reserved1;
    u64 reserved2;
    u64 reserved3;
    i32 ref_count;
    i32 nested_count;
    u32 nested_no_bounds_refcnt;
    u16 hw_asid;
    u8 sw_asid;
    bool reserved4;
    bool pmap_vm_map_cs_enforced;
    bool reserved5;
    u32 reserved6;
    u8 reserved7;
    u8 type;
    bool reserved8;
    bool reserved9;
    bool is_rosetta;
    bool nx_enabled;
    bool is_64bit;
    bool nested_has_no_bounds_ref;
    bool nested_bounds_set;
    bool disable_jop;
    bool reserved11;
};

void print_pmap(struct kfd* kfd, struct pmap* pmap, u64 pmap_kaddr)
{
    print_message("struct pmap @ %016llx", pmap_kaddr);
    print_x64(pmap->tte);
    print_x64(pmap->ttep);
    print_x64(pmap->min);
    print_x64(pmap->max);
    print_x64(pmap->pmap_pt_attr);
    print_x64(pmap->ledger);
    print_x64(pmap->rwlock[0]);
    print_x64(pmap->rwlock[1]);
    print_x64(pmap->pmaps.next);
    print_x64(pmap->pmaps.prev);
    print_x64(pmap->tt_entry_free);
    print_x64(pmap->nested_pmap);
    print_x64(pmap->nested_region_addr);
    print_x64(pmap->nested_region_size);
    print_x64(pmap->nested_region_true_start);
    print_x64(pmap->nested_region_true_end);
    print_x64(pmap->nested_region_asid_bitmap);
    print_x32(pmap->nested_region_asid_bitmap_size);
    print_x64(pmap->reserved0);
    print_x64(pmap->reserved1);
    print_x64(pmap->reserved2);
    print_x64(pmap->reserved3);
    print_i32(pmap->ref_count);
    print_i32(pmap->nested_count);
    print_x32(pmap->nested_no_bounds_refcnt);
    print_x16(pmap->hw_asid);
    print_x8(pmap->sw_asid);
    print_bool(pmap->reserved4);
    print_bool(pmap->pmap_vm_map_cs_enforced);
    print_bool(pmap->reserved5);
    print_x32(pmap->reserved6);
    print_x32(pmap->reserved7);
    print_bool(pmap->reserved8);
    print_bool(pmap->reserved9);
    print_bool(pmap->is_rosetta);
    print_bool(pmap->nx_enabled);
    print_bool(pmap->is_64bit);
    print_bool(pmap->nested_has_no_bounds_ref);
    print_bool(pmap->nested_bounds_set);
    print_bool(pmap->disable_jop);
    print_bool(pmap->reserved11);
    print_x8(pmap->type);
}

#endif /* pmap_h */
