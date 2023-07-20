/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef fileglob_h
#define fileglob_h

struct fileglob {
    struct {
        u64 le_next;
        u64 le_prev;
    } _msglist;
    u32 fg_flag;
    u32 fg_count;
    u32 fg_msgcount;
    i32 fg_lflags;
    u64 fg_cred;
    u64 fg_ops;
    i64 fg_offset;
    u64 fg_data;
    u64 fg_vn_data;
    u64 fg_lock[2];
};

#endif /* fileglob_h */
