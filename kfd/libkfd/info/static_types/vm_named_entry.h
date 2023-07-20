/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef vm_named_entry_h
#define vm_named_entry_h

struct vm_named_entry {
    u64 Lock[2];
    union {
        u64 map;
        u64 copy;
    } backing;
    u64 offset;
    u64 size;
    u64 data_offset;
    u32
        protection:4,
        is_object:1,
        internal:1,
        is_sub_map:1,
        is_copy:1,
        is_fully_owned:1;
};

void print_vm_named_entry(struct kfd* kfd, struct vm_named_entry* named_entry, u64 named_entry_kaddr)
{
    print_message("struct vm_named_entry @ %016llx", named_entry_kaddr);
    print_x64(named_entry->backing.copy);
    print_x64(named_entry->offset);
    print_x64(named_entry->size);
    print_x64(named_entry->data_offset);
    print_i32(named_entry->protection);
    print_bool(named_entry->is_object);
    print_bool(named_entry->internal);
    print_bool(named_entry->is_sub_map);
    print_bool(named_entry->is_copy);
    print_bool(named_entry->is_fully_owned);

    if (!named_entry->is_sub_map) {
        u64 copy_kaddr = named_entry->backing.copy;
        struct vm_map_copy copy = {};
        kread((u64)(kfd), copy_kaddr, &copy, sizeof(copy));
        print_vm_map_copy(kfd, &copy, copy_kaddr);
    }
}

#endif /* vm_named_entry_h */
