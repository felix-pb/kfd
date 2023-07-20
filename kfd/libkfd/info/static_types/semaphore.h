/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef semaphore_h
#define semaphore_h

struct semaphore {
    struct {
        u64 next;
        u64 prev;
    } task_link;
    char waitq[24];
    u64 owner;
    u64 port;
    u32 ref_count;
    i32 count;
};

#endif /* semaphore_h */
