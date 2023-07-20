/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */


#ifndef fileops_h
#define fileops_h

typedef enum {
    DTYPE_VNODE = 1,
    DTYPE_SOCKET,
    DTYPE_PSXSHM,
    DTYPE_PSXSEM,
    DTYPE_KQUEUE,
    DTYPE_PIPE,
    DTYPE_FSEVENTS,
    DTYPE_ATALK,
    DTYPE_NETPOLICY,
    DTYPE_CHANNEL,
    DTYPE_NEXUS
} file_type_t;

struct fileops {
    file_type_t fo_type;
    void* fo_read;
    void* fo_write;
    void* fo_ioctl;
    void* fo_select;
    void* fo_close;
    void* fo_kqfilter;
    void* fo_drain;
};

#endif /* fileops_h */
