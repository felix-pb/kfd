/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef ipc_port_h
#define ipc_port_h

struct ipc_port {
    struct {
        u32 io_bits;
        u32 io_references;
    } ip_object;
    u64 ip_waitq_and_ip_messages[7];
    union {
        u64 ip_receiver;
        u64 ip_destination;
        u32 ip_timestamp;
    };
    union {
        u64 ip_kobject;
        u64 ip_imp_task;
        u64 ip_sync_inheritor_port;
        u64 ip_sync_inheritor_knote;
        u64 ip_sync_inheritor_ts;
    };
    union {
        i32 ip_pid;
        u64 ip_twe;
        u64 ip_pdrequest;
    };
    u64 ip_nsrequest;
    u64 ip_requests;
    union {
        u64 ip_premsg;
        u64 ip_send_turnstile;
    };
    u64 ip_context;
    u32 ip_impcount;
    u32 ip_mscount;
    u32 ip_srights;
    u32 ip_sorights;
    union {
        u64 ip_kolabel;
        u64 ip_splabel;
    };
};

#endif /* ipc_port_h */
