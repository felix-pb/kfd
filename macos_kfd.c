/*
 * Copyright (c) 2023 Félix Poulin-Bélanger. All rights reserved.
 */

#include "kfd/libkfd.h"

int main(void)
{
    u64 kfd = kopen(2048, puaf_smith, kread_sem_open, kwrite_sem_open);
    // At this point, kfd can be used with kread() and kwrite().
    kclose(kfd);
}
