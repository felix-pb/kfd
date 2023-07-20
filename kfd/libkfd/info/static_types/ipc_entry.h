/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef ipc_entry_h
#define ipc_entry_h

struct ipc_entry {
    union {
        u64 ie_object;
        u64 ie_volatile_object;
    };
    u32 ie_bits;
    u32 ie_dist:12;
    u32 ie_index:32;
    union {
        u32 ie_next;
        u32 ie_request;
    };
};

#endif /* ipc_entry_h */
