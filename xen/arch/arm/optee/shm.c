/*
 * xen/arch/arm/optee/smc.c
 *
 * OPTEE SHM dispatcher
 *
 * Volodymyr Babchuk <volodymyr.babchuk@globallogic.com>
 * Copyright (c) 2016 GlobalLogic Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/stdbool.h>
#include <xen/sched.h>

#include <asm/p2m.h>
#include <asm/processor.h>

#include <public/xen.h>

#include "smc.h"
#include "optee.h"
#include "shm.h"
#include "optee_smc.h"

/* Holds information about SHM received from OPTEE */
struct optee_shmem_info {
    paddr_t maddr;
    size_t size;
    bool_t valid;
} optee_shmem_info;

/* Holds per-domain SHM information */
struct domain_shmem_info {
    paddr_t maddr;
    paddr_t gaddr;
    size_t size;
    domid_t domain_id;
    bool_t valid;
};

static struct domain_shmem_info domain_shmem_info[OPTEE_MAX_DOMAINS];
static struct xmem_pool *optee_mempool = 0;

static noinline void *optee_mempool_page_get(unsigned long size)
{
    ASSERT(size == domain_shmem_info[0].size);
    return maddr_to_virt(domain_shmem_info[0].maddr);
}

static void optee_mempool_page_put(void *page_va)
{
    return;
}

static void configure_xen_shm(void)
{
    domain_shmem_info[0].valid = true;
    domain_shmem_info[0].domain_id = DOMID_XEN;

    optee_mempool = xmem_pool_create("optee", optee_mempool_page_get,
                                     optee_mempool_page_put,
                                     domain_shmem_info[0].size,
                                     domain_shmem_info[0].size,
                                     domain_shmem_info[0].size);

}

void* optee_shm_alloc(size_t size)
{
    printk("[2]\n");
    return xmem_pool_alloc(size, optee_mempool);
}

void* optee_shm_zalloc(size_t size)
{
    void *ptr = optee_shm_alloc(size);
    printk("[1]\n");
    if (ptr)
        memset(ptr, 0, size);
    return ptr;
}

void optee_shm_free(void *ptr)
{
    xmem_pool_free(ptr, optee_mempool);
}

void optee_process_get_shm_config(struct cpu_user_regs *regs)
{
    if (!optee_shmem_info.valid) {
        size_t domain_shmem_size;
        paddr_t maddr;

        /* Get config from OPTEE */
        optee_execute_smc(regs);
        optee_shmem_info.maddr = regs->x1;
        optee_shmem_info.size = regs->x2;
        optee_shmem_info.valid = true;
        /* Split OP-TEE shmem region for domains */
        domain_shmem_size =
            (optee_shmem_info.size/OPTEE_MAX_DOMAINS);
        domain_shmem_size -= domain_shmem_size%PAGE_SIZE;
        maddr = optee_shmem_info.maddr;
        for (int i = 0; i < OPTEE_MAX_DOMAINS; i++) {
            domain_shmem_info[i].valid = false;
            domain_shmem_info[i].size = domain_shmem_size;
            domain_shmem_info[i].maddr = maddr;
            domain_shmem_info[i].gaddr = maddr;
            maddr += domain_shmem_size;
        }

        /* We'll use one memory region for XEN itself */
        configure_xen_shm();
    }

    /* Check if memory is already maped for this domain */
    for (int i = 0; i < OPTEE_MAX_DOMAINS; i++) {
        if (domain_shmem_info[i].valid &&
            domain_shmem_info[i].domain_id == current->domain->domain_id) {
            regs->x0 = OPTEE_SMC_RETURN_OK;
            regs->x1 = domain_shmem_info[i].gaddr;
            regs->x2 = domain_shmem_info[i].size;
            regs->x3 = OPTEE_SMC_SHM_CACHED;
            return;
        }
    }

    /* Find free slot and map memory */
    for (int i = 0; i < OPTEE_MAX_DOMAINS; i++) {
        if (domain_shmem_info[i].valid == false) {
            int ret = guest_physmap_add_entry_range(
                current->domain,
                paddr_to_pfn(domain_shmem_info[i].gaddr),
                domain_shmem_info[i].size / PAGE_SIZE,
                paddr_to_pfn(domain_shmem_info[i].maddr),
                p2m_ram_rw);
            if (ret == 0) {
                regs->x0 = OPTEE_SMC_RETURN_OK;
                regs->x1 = domain_shmem_info[i].gaddr;
                regs->x2 = domain_shmem_info[i].size;
                regs->x3 = OPTEE_SMC_SHM_CACHED;
                domain_shmem_info[i].domain_id =
                    current->domain->domain_id;
                domain_shmem_info[i].valid = true;
                return;
            } else {
                regs->x0 = OPTEE_SMC_RETURN_ENOMEM;
                return;
            }
        }
    }

    /* There are no free slots */
    regs->x0 = OPTEE_SMC_RETURN_ENOMEM;
}

void optee_free_domain_shm(domid_t domain_id)
{
    for (int i = 0; i < OPTEE_MAX_DOMAINS; i++) {
	if (domain_shmem_info[i].valid &&
	    domain_shmem_info[i].domain_id == domain_id) {
	    domain_shmem_info[i].valid = false;
	}
    }
}
/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
