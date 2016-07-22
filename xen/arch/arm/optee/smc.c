/*
 * xen/arch/arm/optee/smc.c
 *
 * OPTEE SMC calls proxy/handler
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
#include <xen/list.h>

#include <asm/system.h>
#include <asm/processor.h>
#include <asm/current.h>

#include <xen/sched.h>
#include <asm/event.h>
#include <public/xen.h>

#include "smc.h"
#include "shm.h"
#include "optee.h"
#include "optee_smc.h"
#include "optee_msg.h"

/**
 * We will store opened sessions in the linked list.
 * It is not likely that there will be more than 10-20 concurrent sessions,
 * so this approach looks fine. We can switch to radix tree if there will be
 * any performance issues.
 */

struct optee_session {
	struct list_head list;
	domid_t domain_id;
	unsigned int session_handle;
};

LIST_HEAD(optee_sessions);

/**
 * Store RPC returns in the linked list. In this way we can track them.
 * So we will know when standard SMC call is over.
 */

struct optee_rpc_call{
	struct list_head list;
	domid_t domain_id;
	/* This is OP-TEE thread id. OP-TEE uses it to continue task */
	unsigned int thread_id;
	/* Function that should be called on normal return */
	void(*callback)(struct cpu_user_regs *regs);
};

LIST_HEAD(optee_rpc_calls);

void optee_execute_smc(struct cpu_user_regs *regs)
{
	register_t retval[4];

	call_smc_ext(regs->x0,
	             regs->x1,
	             regs->x2,
	             regs->x3,
	             regs->x4,
	             regs->x5,
	             regs->x6,
	             current->domain->domain_id + 1,
	             retval);
	regs->x0 = retval[0];
	regs->x1 = retval[1];
	regs->x2 = retval[2];
	regs->x3 = retval[3];
}


/**
 * This function shall pass all RPC calls and execute callback
 * on normal return.
 */

static void execute_std_smc(struct cpu_user_regs *regs,
                            void(*callback)(struct cpu_user_regs *regs))
{
	optee_execute_smc(regs);
	if (OPTEE_SMC_RETURN_IS_RPC(regs->x0)) {
		/* Store thread ID, so we can distiguish
		   this call among others */
		struct optee_rpc_call *call_info = xzalloc(struct optee_rpc_call);
		/* TODO: Should we panic there? */
		if(!call_info)
			return;

		call_info->domain_id = current->domain->domain_id;
		call_info->thread_id = regs->x3;
		call_info->callback = callback;
		list_add(&call_info->list, &optee_rpc_calls);
	} else
		callback(regs);
}

static void do_return_from_rpc(struct cpu_user_regs *regs)
{
	struct list_head *list_ptr, *list_next;
	struct optee_rpc_call *call_info;
	list_for_each_safe(list_ptr, list_next, &optee_rpc_calls) {
		call_info = list_entry(list_ptr, struct optee_rpc_call,
		                      list);
		if (call_info->domain_id ==
		    current->domain->domain_id &&
		    call_info->thread_id  == regs->x3) {
			execute_smc(regs);
			if (OPTEE_SMC_RETURN_IS_RPC(regs->x0)) {
				return;
			} else {
				call_info->callback(regs);
				list_del(list_ptr);
				xfree(call_info);
				return;
			}
		}
	}
	execute_smc(regs);
}

static void on_cmd_open_session_done(struct cpu_user_regs *regs)
{
	paddr_t parg = (uint64_t)regs->x1 << 32 | regs->x2;
	volatile struct optee_msg_arg * arg = maddr_to_virt(parg);
	struct optee_session *ses_info;
	if(arg->ret == 0 && regs->x0 == 0) {
		ses_info = xzalloc(struct optee_session);
		/* TODO: Should we panic there? */
		if (!ses_info)
			return;
		ses_info->domain_id =
			current->domain->domain_id;
		ses_info->session_handle = arg->session;
		list_add(&ses_info->list, &optee_sessions);
	}
}

static void on_cmd_close_session_done(struct cpu_user_regs *regs)
{
	paddr_t parg = (uint64_t)regs->x1 << 32 | regs->x2;
	volatile struct optee_msg_arg * arg = maddr_to_virt(parg);
	struct optee_session *ses_info;
	struct list_head *list_ptr, *list_next;

	list_for_each_safe(list_ptr, list_next, &optee_sessions) {
		ses_info = list_entry(list_ptr, struct optee_session,
		                      list);
		if (ses_info->domain_id ==
		    current->domain->domain_id &&
		    ses_info->session_handle == arg->session) {
			list_del(list_ptr);
			xfree(ses_info);
		}
	}
}

static void do_process_handle_call(struct cpu_user_regs *regs)
{
	/* It is standard call. Parameters are held in shared memory
	   w1 & w2 points to structure with parameters */
	paddr_t parg = (uint64_t)regs->x1 << 32 | regs->x2;
	volatile struct optee_msg_arg * arg = maddr_to_virt(parg);

	switch(arg->cmd) {
	case OPTEE_MSG_CMD_OPEN_SESSION:
		/* Execute call and check if it was successul  */
		execute_std_smc(regs, on_cmd_open_session_done);
		break;
	case OPTEE_MSG_CMD_CLOSE_SESSION:
		execute_std_smc(regs, on_cmd_close_session_done);
		break;
	default:
		/* Execute call and check if it was successul  */
		execute_smc(regs);
		break;
	}
}

int optee_handle_smc(struct cpu_user_regs *regs)
{
	uint32_t smc_code = regs->r0;
	switch(smc_code){
	case OPTEE_SMC_GET_SHM_CONFIG:
		optee_process_get_shm_config(regs);
		break;
	case OPTEE_SMC_ENABLE_SHM_CACHE:
		/* We can't allow guests to enable SHM cache */
		/* as OPTEE can cache other guest's SHM      */
		/* So, we will pretend that cache is enabled */
		regs->x0 = OPTEE_SMC_RETURN_OK;
		break;
	case OPTEE_SMC_CALL_WITH_ARG:
		do_process_handle_call(regs);
		break;
	case OPTEE_SMC_CALL_RETURN_FROM_RPC:
		do_return_from_rpc(regs);
		break;
	default:
		/* Just forward request to OPTEE */
		optee_execute_smc(regs);
		break;
	}
	return 0;
}

void optee_domain_destroy(struct domain *d)
{
    optee_free_domain_shm(d->domain_id);
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
