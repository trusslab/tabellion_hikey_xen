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
#include <xen/xmalloc.h>
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
unsigned int sfb_paddr;
unsigned int normal_fb_paddr; /* for unfreezing */

DO(unfreeze_op)(XEN_GUEST_HANDLE_PARAM(void) arg) {

	void* ade_reg;
	ade_reg = ioremap(0xf4100000, 0x1010);

	/* bring it back */
	p2m_set_mem_access(current->domain, _gfn( (0xf4100000)>> PAGE_SHIFT), 1, 0, ~0, XENMEM_access_rw, 0);
	
	/* bring it back */
	p2m_set_mem_access(current->domain, _gfn(sfb_paddr >> PAGE_SHIFT), 1, 0, ~0, XENMEM_access_rw, 0);

	/* Back to normal */
	writel(normal_fb_paddr, ade_reg + 0x1008);
	dsb(sy); isb();

	return 0;
}


/* Wait a set number of microseconds */
extern void udelay(unsigned long usecs);

DO(freeze_op)(XEN_GUEST_HANDLE_PARAM(void) arg) {

	void* sfb1, *sfb2; //secure fb
	void* ade_reg;
	int i;

	unsigned int buff = 0;
	void *tmp;

//	printk("Saeed: Start freeze op\n");

	if( copy_from_guest(&buff, arg, 1) ) {
		printk("SaeedXEN: Error\n");
		return -EFAULT;
	}

	/* write protect before starting */
	/* write protect the ade register */
	p2m_set_mem_access(current->domain, _gfn( (0xf4100000)>> PAGE_SHIFT), 1, 0, ~0, XENMEM_access_r, 0);
	
	/* write protect the secure framebuffer */
	p2m_set_mem_access(current->domain, _gfn(sfb_paddr >> PAGE_SHIFT), 1, 0, ~0, XENMEM_access_r, 0);

//	printk("Saeed: buff=%x\n", (unsigned int)buff);

	/* we don't need to get the address from the OS, we just freeze whatever is on the screen */
	tmp = GPA_to_HPA(buff);

	sfb_paddr = *(unsigned int*)tmp;

	/* find the ade register */
	ade_reg = ioremap(0xf4100000, 0x1010);
	
	normal_fb_paddr = readl(ade_reg + 0x1008);
	
//	printk("SaeedXEN: reg_addr=%lx\n", (unsigned long)ade_reg);

	/* get secure fb addr in Xen */
	sfb1 = GPA_to_HPA(sfb_paddr);
	sfb2 = sfb1 + 8294400;

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

	/* sleep for a few seconds */
	udelay(1000000);

	/* show sfb2 - main page */	
	writel(sfb_paddr + 8294400, ade_reg + 0x1008);
	writel(1, ade_reg + 0x1020);
	dsb(sy); isb();
//	printk("SaeedXEN: reg_addr val after==%lx\n", (unsigned long)readl(ade_reg + 0x1008));

	/* sleep for a few seconds */
	udelay(1000000);

	/* Ask for signature here - Call OPTEE */
//	test_call();

	return  0;
}

void* photo_buffer; /* photo buffer */

DO(prepare_photo_op)(XEN_GUEST_HANDLE_PARAM(void) arg) {
	/*  Set the address of the photo buffer to TEE (Xen) &
	 *  write protect the photo buffer
	 */

	unsigned int buff = 0;

	//p2m_type_t p2mt = p2m_ram_rw;
	//p2m_type_t p2mt = p2m_mmio_direct;
	paddr_t paddr_g_cam;

	printk("Saeed: Xen, prepare photo buf op\n");

	if( copy_from_guest(&buff, arg, 1) ) {
		printk("SaeedXEN: Error\n");
		return -EFAULT;
	}

	paddr_g_cam = buff;

	photo_buffer = GPA_to_HPA(paddr_g_cam);
//	printk("Saeed: Xen, prepare photo buf op, paddr_g_cam = %lx, photo_buffer=%lx\n", (unsigned long) paddr_g_cam, (unsigned long)photo_buffer);

	p2m_set_mem_access(current->domain, _gfn(paddr_g_cam >> PAGE_SHIFT), 1, 0, ~0, XENMEM_access_r, 0);
	return 0;
}

DO(show_photo_op)(XEN_GUEST_HANDLE_PARAM(void) arg) {
	/* Convert YUYV to RGB on the photo buffer
	 * Resize
	 * Show the photo buffer on the secure display, finding the address of it from the register
	 * write protect the sfb
	 */

	void* ade_reg;
	unsigned int sfb_paddr;
	int width=176, height=144;
	int t_width=352, t_height=288; //target width and target height
	unsigned char r, g, b;
	unsigned int sum_r, sum_g, sum_b;
	int xoffset, yoffset;
	
	unsigned int *scaled, *transformed, *fb2_addr;
	unsigned char *tmp;

	int xres = 1920, yres = 1080;
	float xscale, yscale;
	int i, j, ii, jj;
	char transp = 0xFF;
	bool upscale;

	tmp = (unsigned char*)photo_buffer;

//	printk("Saeed: Xen, show photo buf op, photo_buffer=%lx\n", (unsigned long)photo_buffer);
//	printk("Saeed: %s, show_photo_op, [0]=%x\n", __FUNCTION__, readl(photo_buffer));
//	printk("Saeed: %s, show_photo_op, [10]=%x\n", __FUNCTION__, readl(photo_buffer + 10));
//	printk("Saeed: %s, show_photo_op, [20]=%x\n", __FUNCTION__, readl(photo_buffer + 20));
//	printk("Saeed: %s, show_photo_op, [50]=%x\n", __FUNCTION__, readl(photo_buffer + 50));


	transformed = (unsigned int*)xmalloc_array(unsigned int, width * height);
	for(j=0; j<height; j++) {
		for( i=0; i<width/2; i++) {
			int y1, y2, u, v;
			unsigned char r1, g1, b1;
			unsigned char r2, g2, b2;
			
			unsigned int val;

			memcpy(&val, tmp + j*width*2 + 4*i, 4);

		        v  = ((val & 0x000000ff));
		        y2  = ((val & 0x0000ff00)>>8);
			u  = ((val & 0x00ff0000)>>16);
			y1 = ((val & 0xff000000)>>24);

			r1 = y1;
			r2 = y2;
			g1 = u;
			g2 = u;
			b1 = v;
			b2 = v;
	
			transformed[ j*width + 2*i + 0] = transp << 24 | r1 << 16 | g1 << 8 | b1;
			transformed[ j*width + 2*i + 1] = transp << 24 | r2 << 16 | g2 << 8 | b2;
		}
	}

	/* Start upscale downscaling
	 *
	 * transformed -> scaled
	 * width*height -> t_width*t_height
	 * 
	 */	
	xscale = t_width/width;
	yscale = t_height/height;
	scaled = xmalloc_array(unsigned int, t_width * t_height); /* 4 bytes per pixel */

	if (xscale>1 && yscale>1) {
		printk("Upscaling... with xscale=%d, yscale=%d\n", (int)xscale, (int)yscale);
		upscale = true;
	}
	else if (xscale<1 && yscale<1) {
		printk("Downscaling...\n");
		upscale = false;
	}
	else
		printk("Not supported");


	/* Start scaling */
	if (upscale) { // replication
		for (j=0; j<t_height; j++) {
			for(i=0; i<t_width; i++) {
				ii = i/(int)xscale;
				jj = j/(int)yscale;
				scaled[j * t_width + i] = transformed[(jj * width) + ii];
			}
		}
	}
	else { // Downscaling
		yscale = (int)(1/yscale);
		xscale = (int)(1/xscale);
		for(i=0; i<t_width; i++) {
			for (j=0; j<t_height; j++) {
				//average block of them
				//
				sum_r = 0;
				sum_g = 0;
				sum_b = 0;
				for(ii=0; ii<xscale; ii++) {
					for(jj=0; jj<yscale; jj++) {
						unsigned int val;
						val = transformed[ ((int)yscale*j + jj) * t_width + ((int)xscale*i + ii)];
						sum_r += (val & 0x00FF0000) >> 16;
						sum_g += (val & 0x0000FF00) >> 8;
						sum_b += (val & 0x000000FF) >> 0;
					}
				}
				r = (sum_r / (xscale * yscale));
				g = (sum_g / (xscale * yscale));
				b = (sum_b / (xscale * yscale));

				scaled[j * t_width + i] = (transp << 24) | (r << 16) | (g << 8) | b;
			}
		}

	}
	xfree(transformed);

	/* find out the sfb */
	ade_reg = ioremap(0xf4100000, 0x1010);
	sfb_paddr = readl(ade_reg + 0x1008);
//	printk("Saeed: Xen, show photo buf op, sfb_paddr = %lx\n", (unsigned long) sfb_paddr);

	fb2_addr = GPA_to_HPA(sfb_paddr);

	/* positioning the scaled photo buffer on the second framebuffer */
	xoffset = xres/4;
	yoffset = yres/4;
	printk("---------------------------------\n");
	//FIXME: maybe try memcpy
	for (j=0; j<t_height; j++) {
		for(i=0; i<t_width; i++) {
			fb2_addr[ xres * (yoffset + j) + (xoffset + i)] = scaled[j * t_width + i];
		}
	}

	xfree(scaled);
	
//	memcpy(phys_to_virt((unsigned long)(obj->paddr)) + 16588800/2, phys_to_virt((unsigned long)(obj->paddr)), 16588800/2);

	printk("Saeed: Xen, show photo buf op, conversion ended\n");
	return 0;
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
