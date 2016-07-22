/*
 * xen/arch/optee/shm.h
 *
 * OPTEE SHM hadler/manager
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

#ifndef __ARCH_ARM_OPTEE_SHM_H__
#define __ARCH_ARM_OPTEE_SHM_H__

extern void* optee_shm_alloc(size_t size);
extern void* optee_shm_zalloc(size_t size);
extern void optee_shm_free(void *ptr);

extern void optee_process_get_shm_config(struct cpu_user_regs *regs);
extern void optee_free_domain_shm(domid_t domain_id);

#endif

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
