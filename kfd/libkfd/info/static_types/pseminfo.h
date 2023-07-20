/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef pseminfo_h
#define pseminfo_h

struct pseminfo {
    u32 psem_flags;
    u32 psem_usecount;
    u16 psem_mode;
    u32 psem_uid;
    u32 psem_gid;
    char psem_name[32];
    u64 psem_semobject;
    u64 psem_label;
    i32 psem_creator_pid;
    u64 psem_creator_uniqueid;
};

#endif /* pseminfo_h */
