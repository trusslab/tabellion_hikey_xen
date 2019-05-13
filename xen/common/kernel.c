/******************************************************************************
 * kernel.c
 * 
 * Copyright (c) 2002-2005 K A Fraser
 */

#include <xen/init.h>
#include <xen/lib.h>
#include <xen/errno.h>
#include <xen/version.h>
#include <xen/sched.h>
#include <xen/paging.h>
#include <xen/nmi.h>
#include <xen/guest_access.h>
#include <xen/hypercall.h>
#include <xsm/xsm.h>
#include <asm/current.h>
#include <public/nmi.h>
#include <public/version.h>
//Saeed
#include <xen/sizes.h>
#include <xen/mm.h>
#include <asm/p2m.h>
#include <public/memory.h>
#include <xen/domain_page.h>
#include<asm-arm/arm64/io.h>
//#include <delay.h>

//#include <unistd.h>
#ifndef COMPAT

enum system_state system_state = SYS_STATE_early_boot;

int tainted;

xen_commandline_t saved_cmdline;

static void __init assign_integer_param(
    struct kernel_param *param, uint64_t val)
{
    switch ( param->len )
    {
    case sizeof(uint8_t):
        *(uint8_t *)param->var = val;
        break;
    case sizeof(uint16_t):
        *(uint16_t *)param->var = val;
        break;
    case sizeof(uint32_t):
        *(uint32_t *)param->var = val;
        break;
    case sizeof(uint64_t):
        *(uint64_t *)param->var = val;
        break;
    default:
        BUG();
    }
}

void __init cmdline_parse(const char *cmdline)
{
    char opt[100], *optval, *optkey, *q;
    const char *p = cmdline;
    struct kernel_param *param;
    int bool_assert;

    if ( cmdline == NULL )
        return;

    safe_strcpy(saved_cmdline, cmdline);

    for ( ; ; )
    {
        /* Skip whitespace. */
        while ( *p == ' ' )
            p++;
        if ( *p == '\0' )
            break;

        /* Grab the next whitespace-delimited option. */
        q = optkey = opt;
        while ( (*p != ' ') && (*p != '\0') )
        {
            if ( (q-opt) < (sizeof(opt)-1) ) /* avoid overflow */
                *q++ = *p;
            p++;
        }
        *q = '\0';

        /* Search for value part of a key=value option. */
        optval = strchr(opt, '=');
        if ( optval != NULL )
        {
            *optval++ = '\0'; /* nul-terminate the option value */
            q = strpbrk(opt, "([{<");
        }
        else
        {
            optval = q;       /* default option value is empty string */
            q = NULL;
        }

        /* Boolean parameters can be inverted with 'no-' prefix. */
        bool_assert = !!strncmp("no-", optkey, 3);
        if ( !bool_assert )
            optkey += 3;

        for ( param = &__setup_start; param < &__setup_end; param++ )
        {
            if ( strcmp(param->name, optkey) )
            {
                if ( param->type == OPT_CUSTOM && q &&
                     strlen(param->name) == q + 1 - opt &&
                     !strncmp(param->name, opt, q + 1 - opt) )
                {
                    optval[-1] = '=';
                    ((void (*)(const char *))param->var)(q);
                    optval[-1] = '\0';
                }
                continue;
            }

            switch ( param->type )
            {
            case OPT_STR:
                strlcpy(param->var, optval, param->len);
                break;
            case OPT_UINT:
                assign_integer_param(
                    param,
                    simple_strtoll(optval, NULL, 0));
                break;
            case OPT_BOOL:
                if ( !parse_bool(optval) )
                    bool_assert = !bool_assert;
                assign_integer_param(param, bool_assert);
                break;
            case OPT_SIZE:
                assign_integer_param(
                    param,
                    parse_size_and_unit(optval, NULL));
                break;
            case OPT_CUSTOM:
                if ( !bool_assert )
                {
                    if ( *optval )
                        break;
                    safe_strcpy(opt, "no");
                    optval = opt;
                }
                ((void (*)(const char *))param->var)(optval);
                break;
            default:
                BUG();
                break;
            }
        }
    }
}

int __init parse_bool(const char *s)
{
    if ( !strcmp("no", s) ||
         !strcmp("off", s) ||
         !strcmp("false", s) ||
         !strcmp("disable", s) ||
         !strcmp("0", s) )
        return 0;

    if ( !strcmp("yes", s) ||
         !strcmp("on", s) ||
         !strcmp("true", s) ||
         !strcmp("enable", s) ||
         !strcmp("1", s) )
        return 1;

    return -1;
}

/**
 *      print_tainted - return a string to represent the kernel taint state.
 *
 *  'S' - SMP with CPUs not designed for SMP.
 *  'M' - Machine had a machine check experience.
 *  'B' - System has hit bad_page.
 *
 *      The string is overwritten by the next call to print_taint().
 */
char *print_tainted(char *str)
{
    if ( tainted )
    {
        snprintf(str, TAINT_STRING_MAX_LEN, "Tainted: %c%c%c%c",
                 tainted & TAINT_UNSAFE_SMP ? 'S' : ' ',
                 tainted & TAINT_MACHINE_CHECK ? 'M' : ' ',
                 tainted & TAINT_BAD_PAGE ? 'B' : ' ',
                 tainted & TAINT_SYNC_CONSOLE ? 'C' : ' ');
    }
    else
    {
        snprintf(str, TAINT_STRING_MAX_LEN, "Not tainted");
    }

    return str;
}

void add_taint(unsigned flag)
{
    tainted |= flag;
}

extern const initcall_t __initcall_start[], __presmp_initcall_end[],
    __initcall_end[];

void __init do_presmp_initcalls(void)
{
    const initcall_t *call;
    for ( call = __initcall_start; call < __presmp_initcall_end; call++ )
        (*call)();
}

void __init do_initcalls(void)
{
    const initcall_t *call;
    for ( call = __presmp_initcall_end; call < __initcall_end; call++ )
        (*call)();
}

# define DO(fn) long do_##fn

#endif

/*
 * Simple hypercalls.
 */
//Saeed
//

extern void test_call(void);
extern void dump_guest_s1_walk(struct domain *, vaddr_t);
extern void *ioremap(paddr_t, size_t);

void* GPA_to_HPA(unsigned int paddr)
{	
	
	paddr_t paddr_base;
	unsigned long offset;
	void* hpa;
	mfn_t reg_mfn;

	paddr_base = p2m_lookup(current->domain, paddr, NULL);
	if(paddr_base == INVALID_PADDR) {
		printk("INVALID_PADDR\n");
		return 0;
	}
	//printk("SaeedXEN: paddr_base=%lx\n", (unsigned long)paddr_base);
	reg_mfn = ((unsigned long)((paddr_base) >> PAGE_SHIFT));
	//printk("SaeedXEN: reg_mfn=%lx\n", (unsigned long)reg_mfn);

	hpa = map_domain_page_global(reg_mfn);
	//printk("SaeedXEN: hpa=%lx\n", (unsigned long)hpa);

	offset = paddr_base - (reg_mfn << PAGE_SHIFT);
	hpa += offset;
	return hpa;

}
unsigned int sfb_paddr;// = 0x55100000;

DO(unfreeze_op)(XEN_GUEST_HANDLE_PARAM(void) arg) {

	void* ade_reg;
	ade_reg = ioremap(0xf4100000, 0x1010);

	/* bring it back */
	p2m_set_mem_access(current->domain, _gfn( (0xf4100000)>> PAGE_SHIFT), 1, 0, ~0, XENMEM_access_rw, 0);
	
	/* bring it back */
	p2m_set_mem_access(current->domain, _gfn(sfb_paddr >> PAGE_SHIFT), 1, 0, ~0, XENMEM_access_rw, 0);

	/* Back to normal */
	//printk("SaeedXEN: reg_addr val before==%lx\n", (unsigned long)readl(ade_reg + 0x1008));	
	writel(0x54100000, ade_reg + 0x1008); //or the 0x55100000
	dsb(sy); isb();
	//printk("SaeedXEN: reg_addr val after==%lx\n", (unsigned long)readl(ade_reg + 0x1008));
	//
	return 0;

}


/* Wait a set number of microseconds */
extern void udelay(unsigned long usecs);
DO(freeze_op)(XEN_GUEST_HANDLE_PARAM(void) arg) {

	void* fb1, *fb2;
	void* sfb1, *sfb2; //secure fb
	void* ade_reg;
	int i;

//	unsigned int sfb_paddr;// = 0x55100000;
	unsigned int fb_paddr = 0x56100000;


//	unsigned int old_buf;
//	int i, j;
////	u32 val;
	unsigned int buff = 0;
	void *tmp;
////
//////	mfn_t old_buf_mfn;
//	mfn_t reg_mfn;
////
//////	paddr_t paddr;
//	paddr_t paddr_base;
//////	unsigned long pfn;
//	unsigned long val;
////	p2m_type_t p2mt = p2m_ram_rw;
//	//p2m_type_t p2mt = p2m_mmio_direct;
//	unsigned long offset;
////	u32 reg_addr = 0x1008;
//	paddr_t paddr_g = 0x54100000;
//////	paddr_t base = 0xf4100000;
//
////	paddr_t base = 0xf4100000 + reg_addr;
////	paddr_t base2 = 0x9b68000;
//
//	printk("Saeed: Start freeze op\n");

	if( copy_from_guest(&buff, arg, 1) ) {
		printk("SaeedXEN: Error\n");
		return -EFAULT;
	}
//	printk("Saeed: buff=%x\n", (unsigned int)buff);
	tmp = GPA_to_HPA(buff);

	sfb_paddr = *(unsigned int*)tmp;

	/* find the ade register */
	ade_reg = ioremap(0xf4100000, 0x1010);
//	printk("SaeedXEN: reg_addr=%lx\n", (unsigned long)ade_reg);

	/* get secure fb addr in Xen */
	sfb1 = GPA_to_HPA(sfb_paddr);
	sfb2 = sfb1 + 8294400;
//	printk("sfb1=%lx\n", (unsigned long)sfb1);
//	printk("sfb2=%lx\n", (unsigned long)sfb2);
//	printk("test val1=%x, ", readl(sfb1));
//	printk("test val2=%x\n", readl(sfb2));

	/* get normal fb addr in Xen */
	fb1 = GPA_to_HPA(fb_paddr);
	fb2 = fb1 + 8294400;
//	printk("fb1=%lx\n", (unsigned long)fb1);
//	printk("fb2=%lx\n", (unsigned long)fb2);
//	printk("test val1=%x", readl(sfb1));
//	printk("test val2=%x", readl(sfb2));

	//gvaddr = 0xffffff8009b70000;
	//val = readl(base + reg_addr);	

//	//////////// Reading the value at phys addr passed as argument
//	paddr_base = p2m_lookup(current->domain, buff, NULL);
//	if(paddr_base == INVALID_PADDR) {
//		goto end;
//	}
//	printk("SaeedXEN: paddr_base1=%lx\n", (unsigned long)paddr_base);
//	reg_mfn = ((unsigned long)((paddr_base) >> PAGE_SHIFT));
//	printk("SaeedXEN: reg_mfn1=%lx\n", (unsigned long)reg_mfn);
//
//	reg_buf = map_domain_page_global(reg_mfn);
//	printk("SaeedXEN: reg_buf1=%lx\n", (unsigned long)reg_buf);
//
//	offset = paddr_base - (reg_mfn << PAGE_SHIFT);
//	
//	val = readw(reg_buf + offset);
//	printk("SaeedXEN: reg val_w=%lx\n", (unsigned long)val);
//	val = readl(reg_buf + offset);
//	printk("SaeedXEN: reg val_l=%lx\n", (unsigned long)val);
//
//	/////////////Reading pixel values
//	paddr_base = p2m_lookup(current->domain, paddr_g, NULL);
//	if(paddr_base == INVALID_PADDR) {
//		goto end;
//	}
//	printk("SaeedXEN: paddr_base1=%lx\n", (unsigned long)paddr_base);
//	reg_mfn = ((unsigned long)((paddr_base) >> PAGE_SHIFT));
//	printk("SaeedXEN: reg_mfn1=%lx\n", (unsigned long)reg_mfn);
//
//	reg_buf = map_domain_page_global(reg_mfn);
//	printk("SaeedXEN: reg_buf1=%lx\n", (unsigned long)reg_buf);
//
//	offset = paddr_base - (reg_mfn << PAGE_SHIFT);
//	
//	val = readl(reg_buf + offset);
//	printk("SaeedXEN: pix=%lx\n", (unsigned long)val);
//	val = readl(reg_buf + offset + 4);
//	printk("SaeedXEN: pix=%lx\n", (unsigned long)val);
//	val = readl(reg_buf + offset + 8);
//	printk("SaeedXEN: reg val_l=%lx\n", (unsigned long)val);


	/* Write white page to the first sfb */
	for(i=0; i<2073600; i++) {
		writel(0xffffffff, sfb1 + 4*i);
	}

	/* Update the ade to sfb1*/
//	printk("SaeedXEN: reg_addr val before==%lx\n", (unsigned long)readl(ade_reg + 0x1008));	
	writel(sfb_paddr, ade_reg + 0x1008);
	writel(1, ade_reg + 0x1020);
	dsb(sy); isb();
//	printk("SaeedXEN: reg_addr val after==%lx\n", (unsigned long)readl(ade_reg + 0x1008));

//	for(i=0; i<573600; i++) {
//		writel(0xffffffff, sfb2 + 4*i);
//	}



	
	//
//	//Copy current FB to a new FB
//	//
//	//
//	//New FB:
////	new_buf = _xzalloc(1920*1280*8, SZ_64M);
//
//	//old buf
//	// paddr_g -> mfn
//	//
///	paddr = p2m_lookup(current->domain, paddr_g, NULL);
////	old_buf_mfn = ((unsigned long)((paddr) >> PAGE_SHIFT));
////	old_buf = map_domain_page_global(old_buf_mfn);
////	memcpy(new_buf, old_buf, 16588800);	
//
//	//Update the register
//	//
	//paddr_base = p2m_lookup(current->domain, buff << PAGE_SHIFT, &p2mt);
	//

//	printk("Saeed: Dump start\n");
//	dump_guest_s1_walk(current->domain, 0xffffff8009b70000);
//
//	paddr_base = p2m_lookup(current->domain, base, NULL);
//	paddr_base = p2m_lookup(current->domain, (base >> PAGE_SHIFT) << PAGE_SHIFT, NULL);
//	if(paddr_base == INVALID_PADDR) {
//		goto end;
//	}
//	printk("SaeedXEN: paddr_base1=%lx\n", (unsigned long)paddr_base);
//	//offset = buff - paddr_base;
//	//printk("SaeedXEN: offset1=%lx\n", (unsigned long)offset);
//	reg_mfn = (paddr_base) >> PAGE_SHIFT;
//	printk("SaeedXEN: reg_mfn1=%lx\n", (unsigned long)reg_mfn);
//	offset = paddr_base - (reg_mfn << PAGE_SHIFT);
//	//offset = reg_addr;
//	printk("SaeedXEN: offset1=%lx\n", (unsigned long)offset);
//	reg_buf = map_domain_page_global(_mfn(reg_mfn));
//	printk("SaeedXEN: reg_buf1=%lx\n", (unsigned long)reg_buf);
//	val = readl(reg_buf + offset);
//	printk("SaeedXEN: reg val1=%lx\n", (unsigned long)val);

	//reg_buf = ioremap(0xf4100000, 0x1008);
	//usleep(1000*1000*2);
	
	/* sleep for a few seconds */
	udelay(1000000);

	/* show sfb2 - main page */
//	printk("SaeedXEN: reg_addr val before==%lx\n", (unsigned long)readl(ade_reg + 0x1008));	
	
	
	writel(sfb_paddr + 8294400, ade_reg + 0x1008); //or the 0x55100000
	writel(1, ade_reg + 0x1020);
	dsb(sy); isb();
//	printk("SaeedXEN: reg_addr val after==%lx\n", (unsigned long)readl(ade_reg + 0x1008));

	/* sleep for a few seconds */
	// udelay(1000000);
	//
	//
	
	/* write protect the ade register */
	p2m_set_mem_access(current->domain, _gfn( (0xf4100000)>> PAGE_SHIFT), 1, 0, ~0, XENMEM_access_r, 0);
	
	/* write protect the secure framebuffer */
	p2m_set_mem_access(current->domain, _gfn(sfb_paddr >> PAGE_SHIFT), 1, 0, ~0, XENMEM_access_r, 0);

	/* Ask for signature here - Call OPTEE */
//	test_call();

//	//MOVED TO UNFREEZE_UI
//	/* Back to normal */
//	printk("SaeedXEN: reg_addr val before==%lx\n", (unsigned long)readl(ade_reg + 0x1008));	
//	writel(0x54100000, ade_reg + 0x1008); //or the 0x55100000
//	dsb(sy); isb();
//	printk("SaeedXEN: reg_addr val after==%lx\n", (unsigned long)readl(ade_reg + 0x1008));


//	val = *(int*)(reg_buf + offset);
//	printk("SaeedXEN: reg val11=%d\n", (int)val);
//	printk("SaeedXEN: reg val11=%lx\n", val);
//
//	paddr_base = p2m_lookup(current->domain, base2, NULL);
//	printk("SaeedXEN: paddr_base2=%lx\n", (unsigned long)paddr_base);
//	reg_mfn = ((unsigned long)((paddr_base) >> PAGE_SHIFT));
//	printk("SaeedXEN: reg_mfn2=%lx\n", (unsigned long)reg_mfn);
//	reg_buf = map_domain_page_global(reg_mfn);
//	printk("SaeedXEN: reg_buf2=%lx\n", (unsigned long)reg_buf);
//	val = readl(reg_buf + reg_addr);
//	printk("SaeedXEN: reg val2=%lx\n", (unsigned long)val);
//	val = *(unsigned int*)(reg_buf + reg_addr);
//	printk("SaeedXEN: reg val22=%lx\n", (unsigned long)val);
//	// new_buf to guest VA
//
////	paddr = p2m_lookup(current->domain, base + reg_addr, NULL);
//
//
////	pfn = paddr_to_pfn(base + reg_addr);
//	
////	_mfn(paddr_to_pfn(base + reg_addr);
//
//
////	printk("[6]: ptr = %lx\n", (unsigned long)readl((void*) ptr));
//
//	//mfn_to_virt
//	//__va(x)
//	//
//	//
////	p2m_lookup(current->domain, paddr, NULL);
//
//	printk("Saeed: End freeze op\n");
//
	return  0;
}

DO(camera_op)(XEN_GUEST_HANDLE_PARAM(void) arg) {

////	void *old_buf;
////	void* new_buf;
	void* dma_buf;
	void* frame_buf;
	int j;
//	u32 val;
	unsigned int buff = 0;
//
////	mfn_t old_buf_mfn;
	mfn_t reg_mfn;
//
////	paddr_t paddr;
	paddr_t paddr_base;
////	unsigned long pfn;
	unsigned long val;
//	p2m_type_t p2mt = p2m_ram_rw;
	//p2m_type_t p2mt = p2m_mmio_direct;
	unsigned long offset;
//	u32 reg_addr = 0x1008;
	paddr_t paddr_g_fb = 0x54100000; //FB
	paddr_t paddr_g_cam = 0x54700000; //Camera, wrong might be different each time
////	paddr_t base = 0xf4100000;

//	paddr_t base = 0xf4100000 + reg_addr;
//	paddr_t base2 = 0x9b68000;
//
//
	printk("Saeed: Xen start camera op\n");

	if( copy_from_guest(&buff, arg, 1) ) {
		printk("SaeedXEN: Error\n");
		return -EFAULT;
	}

	//gvaddr = 0xffffff8009b70000;
	//val = readl(base + reg_addr);	
	printk("Saeed: %lx\n", (unsigned long)buff);
	paddr_g_cam = buff;

//	//////////// Reading the value at phys addr passed as argument
//	paddr_base = p2m_lookup(current->domain, buff, NULL);
//	if(paddr_base == INVALID_PADDR) {
//		goto end;
//	}
//	printk("SaeedXEN: paddr_base1=%lx\n", (unsigned long)paddr_base);
//	reg_mfn = ((unsigned long)((paddr_base) >> PAGE_SHIFT));
//	printk("SaeedXEN: reg_mfn1=%lx\n", (unsigned long)reg_mfn);
//
//	reg_buf = map_domain_page_global(reg_mfn);
//	printk("SaeedXEN: reg_buf1=%lx\n", (unsigned long)reg_buf);
//
//	offset = paddr_base - (reg_mfn << PAGE_SHIFT);
//	
//	val = readw(reg_buf + offset);
//	printk("SaeedXEN: reg val_w=%lx\n", (unsigned long)val);
//	val = readl(reg_buf + offset);
//	printk("SaeedXEN: reg val_l=%lx\n", (unsigned long)val);



	/////////////Reading camera buffer
	paddr_base = p2m_lookup(current->domain, paddr_g_cam, NULL);
	if(paddr_base == INVALID_PADDR) {
		goto end;
	}
	printk("SaeedXEN: paddr_base1=%lx\n", (unsigned long)paddr_base);
	reg_mfn = ((unsigned long)((paddr_base) >> PAGE_SHIFT));
	printk("SaeedXEN: reg_mfn1=%lx\n", (unsigned long)reg_mfn);

	dma_buf = map_domain_page_global(reg_mfn);
	printk("SaeedXEN: reg_buf1=%lx\n", (unsigned long)dma_buf);

	offset = paddr_base - (reg_mfn << PAGE_SHIFT);
	
	val = readl(dma_buf + offset);
	printk("SaeedXEN: reg val_l=%lx\n", (unsigned long)val);


	/////////////Reading frame buffer
	paddr_base = p2m_lookup(current->domain, paddr_g_fb, NULL);
	if(paddr_base == INVALID_PADDR) {
		goto end;
	}
	printk("SaeedXEN: paddr_base1=%lx\n", (unsigned long)paddr_base);
	reg_mfn = ((unsigned long)((paddr_base) >> PAGE_SHIFT));
	printk("SaeedXEN: reg_mfn1=%lx\n", (unsigned long)reg_mfn);

	frame_buf = map_domain_page_global(reg_mfn);
	printk("SaeedXEN: reg_buf1=%lx\n", (unsigned long)dma_buf);

	offset = paddr_base - (reg_mfn << PAGE_SHIFT);
	
	val = readl(frame_buf + offset);
	printk("SaeedXEN: reg val_l=%lx\n", (unsigned long)val);


	memcpy(frame_buf, dma_buf, 204800); //Display camera buf into fb for 5*40960 = 204800 bytes


	// comment for now
//	p2m_set_mem_access(current->domain, _gfn(base >> PAGE_SHIFT), 1, 0, ~0, XENMEM_access_r, 0);


	
	
	//sleep
	for(j=0; j<500000; j+=2) {
		j--;
	}
	for(j=0; j<500000; j+=2) {
		j--;
	}
	for(j=0; j<500000; j+=2) {
		j--;
	}
	for(j=0; j<500000; j+=2) {
		j--;
	}


end:
	test_call();

	printk("Saeed: End camera op\n");

	return  0;
}

DO(xen_version)(int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    bool_t deny = !!xsm_xen_version(XSM_OTHER, cmd);

    switch ( cmd )
    {
    case XENVER_version:
        return (xen_major_version() << 16) | xen_minor_version();

    case XENVER_extraversion:
    {
        xen_extraversion_t extraversion;

        memset(extraversion, 0, sizeof(extraversion));
        safe_strcpy(extraversion, deny ? xen_deny() : xen_extra_version());
        if ( copy_to_guest(arg, extraversion, ARRAY_SIZE(extraversion)) )
            return -EFAULT;
        return 0;
    }

    case XENVER_compile_info:
    {
        xen_compile_info_t info;

        memset(&info, 0, sizeof(info));
        safe_strcpy(info.compiler,       deny ? xen_deny() : xen_compiler());
        safe_strcpy(info.compile_by,     deny ? xen_deny() : xen_compile_by());
        safe_strcpy(info.compile_domain, deny ? xen_deny() : xen_compile_domain());
        safe_strcpy(info.compile_date,   deny ? xen_deny() : xen_compile_date());
        if ( copy_to_guest(arg, &info, 1) )
            return -EFAULT;
        return 0;
    }

    case XENVER_capabilities:
    {
        xen_capabilities_info_t info;

        memset(info, 0, sizeof(info));
        if ( !deny )
            arch_get_xen_caps(&info);

        if ( copy_to_guest(arg, info, ARRAY_SIZE(info)) )
            return -EFAULT;
        return 0;
    }
    
    case XENVER_platform_parameters:
    {
        xen_platform_parameters_t params = {
            .virt_start = HYPERVISOR_VIRT_START
        };

        if ( copy_to_guest(arg, &params, 1) )
            return -EFAULT;
        return 0;
        
    }
    
    case XENVER_changeset:
    {
        xen_changeset_info_t chgset;

        memset(chgset, 0, sizeof(chgset));
        safe_strcpy(chgset, deny ? xen_deny() : xen_changeset());
        if ( copy_to_guest(arg, chgset, ARRAY_SIZE(chgset)) )
            return -EFAULT;
        return 0;
    }

    case XENVER_get_features:
    {
        xen_feature_info_t fi;
        struct domain *d = current->domain;

        if ( copy_from_guest(&fi, arg, 1) )
            return -EFAULT;

        switch ( fi.submap_idx )
        {
        case 0:
            fi.submap = (1U << XENFEAT_memory_op_vnode_supported);
            if ( VM_ASSIST(d, pae_extended_cr3) )
                fi.submap |= (1U << XENFEAT_pae_pgdir_above_4gb);
            if ( paging_mode_translate(d) )
                fi.submap |= 
                    (1U << XENFEAT_writable_page_tables) |
                    (1U << XENFEAT_auto_translated_physmap);
            if ( is_hardware_domain(d) )
                fi.submap |= 1U << XENFEAT_dom0;
#ifdef CONFIG_X86
            switch ( d->guest_type )
            {
            case guest_type_pv:
                fi.submap |= (1U << XENFEAT_mmu_pt_update_preserve_ad) |
                             (1U << XENFEAT_highmem_assist) |
                             (1U << XENFEAT_gnttab_map_avail_bits);
                break;
            case guest_type_pvh:
                fi.submap |= (1U << XENFEAT_hvm_safe_pvclock) |
                             (1U << XENFEAT_supervisor_mode_kernel) |
                             (1U << XENFEAT_hvm_callback_vector);
                break;
            case guest_type_hvm:
                fi.submap |= (1U << XENFEAT_hvm_safe_pvclock) |
                             (1U << XENFEAT_hvm_callback_vector) |
                             (1U << XENFEAT_hvm_pirqs);
                break;
            }
#endif
            break;
        default:
            return -EINVAL;
        }

        if ( __copy_to_guest(arg, &fi, 1) )
            return -EFAULT;
        return 0;
    }

    case XENVER_pagesize:
        if ( deny )
            return 0;
        return (!guest_handle_is_null(arg) ? -EINVAL : PAGE_SIZE);

    case XENVER_guest_handle:
    {
        xen_domain_handle_t hdl;

        if ( deny )
            memset(&hdl, 0, ARRAY_SIZE(hdl));

        BUILD_BUG_ON(ARRAY_SIZE(current->domain->handle) != ARRAY_SIZE(hdl));

        if ( copy_to_guest(arg, deny ? hdl : current->domain->handle,
                           ARRAY_SIZE(hdl) ) )
            return -EFAULT;
        return 0;
    }

    case XENVER_commandline:
    {
        size_t len = ARRAY_SIZE(saved_cmdline);

        if ( deny )
            len = strlen(xen_deny()) + 1;

        if ( copy_to_guest(arg, deny ? xen_deny() : saved_cmdline, len) )
            return -EFAULT;
        return 0;
    }

    case XENVER_build_id:
    {
        xen_build_id_t build_id;
        unsigned int sz;
        int rc;
        const void *p;

        if ( deny )
            return -EPERM;

        /* Only return size. */
        if ( !guest_handle_is_null(arg) )
        {
            if ( copy_from_guest(&build_id, arg, 1) )
                return -EFAULT;

            if ( build_id.len == 0 )
                return -EINVAL;
        }

        rc = xen_build_id(&p, &sz);
        if ( rc )
            return rc;

        if ( guest_handle_is_null(arg) )
            return sz;

        if ( sz > build_id.len )
            return -ENOBUFS;

        if ( copy_to_guest_offset(arg, offsetof(xen_build_id_t, buf), p, sz) )
            return -EFAULT;

        return sz;
    }
    }

    return -ENOSYS;
}

DO(nmi_op)(unsigned int cmd, XEN_GUEST_HANDLE_PARAM(void) arg)
{
    struct xennmi_callback cb;
    long rc = 0;

    switch ( cmd )
    {
    case XENNMI_register_callback:
        rc = -EFAULT;
        if ( copy_from_guest(&cb, arg, 1) )
            break;
        rc = register_guest_nmi_callback(cb.handler_address);
        break;
    case XENNMI_unregister_callback:
        rc = unregister_guest_nmi_callback();
        break;
    default:
        rc = -ENOSYS;
        break;
    }

    return rc;
}

#ifdef VM_ASSIST_VALID
DO(vm_assist)(unsigned int cmd, unsigned int type)
{
    return vm_assist(current->domain, cmd, type, VM_ASSIST_VALID);
}
#endif

DO(ni_hypercall)(void)
{
    /* No-op hypercall. */
    return -ENOSYS;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
