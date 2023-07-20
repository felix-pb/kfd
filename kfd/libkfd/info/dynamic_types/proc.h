/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef proc_h
#define proc_h

struct proc {
    u64 p_list_le_next;
    u64 p_list_le_prev;
    u64 p_pid;
    u64 p_fd_fd_ofiles;
    u64 object_size;
};

const struct proc proc_versions[] = {
    { .p_list_le_next = 0x0, .p_list_le_prev = 0x8, .p_pid = 0x60, .p_fd_fd_ofiles = 0xf8, .object_size = 0x538 },
    { .p_list_le_next = 0x0, .p_list_le_prev = 0x8, .p_pid = 0x60, .p_fd_fd_ofiles = 0xf8, .object_size = 0x730 },
    { .p_list_le_next = 0x0, .p_list_le_prev = 0x8, .p_pid = 0x60, .p_fd_fd_ofiles = 0xf8, .object_size = 0x580 },
    { .p_list_le_next = 0x0, .p_list_le_prev = 0x8, .p_pid = 0x60, .p_fd_fd_ofiles = 0xf8, .object_size = 0x778 },
};

typedef u64 proc_p_list_le_next_t;
typedef u64 proc_p_list_le_prev_t;
typedef i32 proc_p_pid_t;
typedef u64 proc_p_fd_fd_ofiles_t;

#endif /* proc_h */
