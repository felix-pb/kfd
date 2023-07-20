/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef uthread_h
#define uthread_h

struct uthread {
    u64 object_size;
};

const struct uthread uthread_versions[] = {
    { .object_size = 0x200 },
    { .object_size = 0x200 },
    { .object_size = 0x1b0 },
    { .object_size = 0x1b0 },
};

#endif /* uthread_h */
