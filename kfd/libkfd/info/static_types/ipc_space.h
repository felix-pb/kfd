/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef ipc_space_h
#define ipc_space_h

struct ipc_space {
    u64 is_lock[2];
    u32 is_bits;
    u32 is_table_hashed;
    u32 is_table_free;
    u64 is_table;
    u64 is_task;
    u64 is_grower;
    u64 is_label;
    u32 is_low_mod;
    u32 is_high_mod;
    struct {
        u32 seed[4];
        u32 state;
        u64 lock[2];
    } bool_gen;
    u32 is_entropy[1];
    i32 is_node_id;
};

#endif /* ipc_space_h */
