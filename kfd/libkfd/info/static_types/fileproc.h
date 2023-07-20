/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef fileproc_h
#define fileproc_h

struct fileproc {
    u32 fp_iocount;
    u32 fp_vflags;
    u16 fp_flags;
    u16 fp_guard_attrs;
    u64 fp_glob;
    union {
        u64 fp_wset;
        u64 fp_guard;
    };
};

#endif /* fileproc_h */
