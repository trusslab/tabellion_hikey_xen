/*
 * xen/arch/arm/optee/call.c
 *
 * OPTEE STD calls originator/handler
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
#include <xen/delay.h>
#include <xen/lib.h>

#include <asm/system.h>
#include <asm/processor.h>
#include <asm/current.h>

#include <xen/sched.h>
#include <public/xen.h>

#include "shm.h"
#include "call.h"
#include "optee_smc.h"
#include "optee_msg.h"

static void handle_rpc_internal(register_t args[7]);

u32 optee_do_call_with_arg(struct domain *d, paddr_t parg)
{
    register_t param[7] = { };
    register_t retvals[4];
    u32 ret;

    param[0] = OPTEE_SMC_CALL_WITH_ARG;
    param[1] = parg >> 32;
    param[2] = parg & 0xFFFFFFFF;
    while (true) {
        call_smc_ext(param[0], param[1], param[2], param[3],
                     param[4], param[5], param[6],
                     d->domain_id + 1, retvals);

        if (retvals[0] == OPTEE_SMC_RETURN_ETHREAD_LIMIT) {
            /*
             * Out of threads in secure world, wait for a thread
             * become available.
             */
            mdelay(10);
        } else if (OPTEE_SMC_RETURN_IS_RPC(retvals[0])) {
            param[0] = retvals[0];
            param[1] = retvals[1];
            param[2] = retvals[2];
            param[3] = retvals[3];
            handle_rpc_internal(param);
        } else {
            ret = retvals[0];
            break;
        }
    }
    /*
     * We're done with our thread in secure world, if there's any
     * thread waiters wake up one.
     */
    return ret;
}

static void handle_rpc_func_cmd(void* shm)
{
    struct optee_msg_arg *arg = shm;
    struct optee_msg_param *params;
    arg->ret = 0;
    switch(arg->cmd) {
    case OPTEE_MSG_RPC_CMD_WAIT_QUEUE:
        params = OPTEE_MSG_GET_PARAMS(arg);
        switch(params->u.value.a) {
        case OPTEE_MSG_RPC_WAIT_QUEUE_SLEEP:
            /* XEN has no thread, so we can't block it */
            mdelay(1);
            break;
        case OPTEE_MSG_RPC_WAIT_QUEUE_WAKEUP:
            break;
        }
        break;
    default:
        break;
    }
}

static void handle_rpc_internal(register_t args[7])
{
    void *shm;
    paddr_t shm_pa;
    switch (args[0]) {
    case OPTEE_SMC_RETURN_RPC_ALLOC:
	shm = optee_shm_alloc(args[1]);
	if (shm) {
            shm_pa = virt_to_maddr(shm);
            args[1] = shm_pa >> 32;
            args[2] = shm_pa & 0xFFFFFFFF;
            args[4] = (unsigned long)shm >> 32;
            args[5] = (unsigned long)shm & 0xFFFFFFFF;
	} else {
	    args[1] = 0;
	    args[2] = 0;
	    args[4] = 0;
	    args[5] = 0;
	}
	break;
    case OPTEE_SMC_RETURN_RPC_FREE:
	shm = (void*)( args[1] << 32 | args[2]);
	optee_shm_free(shm);
	break;
    case OPTEE_SMC_RETURN_RPC_IRQ:
	break;
    case OPTEE_SMC_RETURN_RPC_CMD:
        shm = (void*)(args[1] << 32 | args[2]);
	handle_rpc_func_cmd(shm);
	break;
    }
    args[0] = OPTEE_SMC_CALL_RETURN_FROM_RPC;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
