/*
 * ARM Generic Interrupt Controller support
 *
 * Tim Deegan <tim@xen.org>
 * Copyright (c) 2011 Citrix Systems.
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

#ifndef __ASM_ARM_GIC_H__
#define __ASM_ARM_GIC_H__

#define NR_GIC_LOCAL_IRQS  NR_LOCAL_IRQS
#define NR_GIC_SGI         16

#define GICD_CTLR       	(0x000)
#define GICD_TYPER      	(0x004)
#define GICD_IIDR       	(0x008)
#define GICD_IGROUPR    	(0x080)
#define GICD_IGROUPRN   	(0x0FC)
#define GICD_ISENABLER  	(0x100)
#define GICD_ISENABLERN 	(0x17C)
#define GICD_ICENABLER  	(0x180)
#define GICD_ICENABLERN 	(0x1fC)
#define GICD_ISPENDR    	(0x200)
#define GICD_ISPENDRN   	(0x27C)
#define GICD_ICPENDR    	(0x280)
#define GICD_ICPENDRN   	(0x2FC)
#define GICD_ISACTIVER  	(0x300)
#define GICD_ISACTIVERN 	(0x37C)
#define GICD_ICACTIVER  	(0x380)
#define GICD_ICACTIVERN 	(0x3FC)
#define GICD_IPRIORITYR 	(0x400)
#define GICD_IPRIORITYRN 	(0x7F8)
#define GICD_ITARGETSR  	(0x800)
#define GICD_ITARGETSR7 	(0x81C)
#define GICD_ITARGETSR8 	(0x820)
#define GICD_ITARGETSRN 	(0xBF8)
#define GICD_ICFGR      	(0xC00)
#define GICD_ICFGR1     	(0xC04)
#define GICD_ICFGR2     	(0xC08)
#define GICD_ICFGRN     	(0xCFC)
#define GICD_NSACR      	(0xE00)
#define GICD_NSACRN     	(0xEFC)
#define GICD_SGIR       	(0xF00)
#define GICD_CPENDSGIR  	(0xF10)
#define GICD_CPENDSGIRN 	(0xF1C)
#define GICD_SPENDSGIR  	(0xF20)
#define GICD_SPENDSGIRN 	(0xF2C)
#define GICD_ICPIDR2    	(0xFE8)

#define GICD_SGI_TARGET_LIST_SHIFT   (24)
#define GICD_SGI_TARGET_LIST_MASK    (0x3UL << GICD_SGI_TARGET_LIST_SHIFT)
#define GICD_SGI_TARGET_SHIFT        (16)
#define GICD_SGI_TARGET_MASK         (0xFFUL << GICD_SGI_TARGET_SHIFT)
#define GICD_SGI_GROUP1              (1UL << 15)
#define GICD_SGI_INTID_MASK          (0xFUL)
#define GICD_SGI_TARGET_OTHERS       (1UL << GICD_SGI_TARGET_LIST_SHIFT)
#define GICD_SGI_TARGET_SELF         (2UL << GICD_SGI_TARGET_LIST_SHIFT)
#define GICD_SGI_TARGET_LIST         (0UL << GICD_SGI_TARGET_LIST_SHIFT)

#define GICC_CTLR       	(0x0000)
#define GICC_PMR        	(0x0004)
#define GICC_BPR        	(0x0008)
#define GICC_IAR        	(0x000C)
#define GICC_EOIR       	(0x0010)
#define GICC_RPR        	(0x0014)
#define GICC_HPPIR      	(0x0018)
#define GICC_APR        	(0x00D0)
#define GICC_NSAPR      	(0x00E0)
#define GICC_IIDR       	(0x00FC)
#define GICC_DIR        	(0x1000)

#define GICH_HCR        	(0x00)
#define GICH_VTR        	(0x04)
#define GICH_VMCR       	(0x08)
#define GICH_MISR       	(0x10)
#define GICH_EISR0      	(0x20)
#define GICH_EISR1      	(0x24)
#define GICH_ELSR0      	(0x30)
#define GICH_ELSR1      	(0x34)
#define GICH_APR        	(0xF0)
#define GICH_LR         	(0x100)

/* Register bits */
#define GICD_CTL_ENABLE 	0x1

#define GICD_TYPE_LINES 	0x01f
#define GICD_TYPE_CPUS_SHIFT 	5
#define GICD_TYPE_CPUS  	0x0e0
#define GICD_TYPE_SEC   	0x400
#define GICD_TYPER_DVIS 	(1U << 18)

#define GICC_CTL_ENABLE 	0x1
#define GICC_CTL_EOI    	(0x1 << 9)

#define GICC_IA_IRQ       	0x03ff
#define GICC_IA_CPU_MASK  	0x1c00
#define GICC_IA_CPU_SHIFT 	10

#define GICH_HCR_EN       	(1 << 0)
#define GICH_HCR_UIE      	(1 << 1)
#define GICH_HCR_LRENPIE  	(1 << 2)
#define GICH_HCR_NPIE     	(1 << 3)
#define GICH_HCR_VGRP0EIE 	(1 << 4)
#define GICH_HCR_VGRP0DIE 	(1 << 5)
#define GICH_HCR_VGRP1EIE 	(1 << 6)
#define GICH_HCR_VGRP1DIE 	(1 << 7)

#define GICH_MISR_EOI     	(1 << 0)
#define GICH_MISR_U       	(1 << 1)
#define GICH_MISR_LRENP   	(1 << 2)
#define GICH_MISR_NP      	(1 << 3)
#define GICH_MISR_VGRP0E  	(1 << 4)
#define GICH_MISR_VGRP0D  	(1 << 5)
#define GICH_MISR_VGRP1E  	(1 << 6)
#define GICH_MISR_VGRP1D  	(1 << 7)

/*
 * The minimum GICC_BPR is required to be in the range 0-3. We set
 * GICC_BPR to 0 but we must expect that it might be 3. This means we
 * can rely on premption between the following ranges:
 * 0xf0..0xff
 * 0xe0..0xdf
 * 0xc0..0xcf
 * 0xb0..0xbf
 * 0xa0..0xaf
 * 0x90..0x9f
 * 0x80..0x8f
 *
 * Priorities within a range will not preempt each other.
 *
 * A GIC must support a mimimum of 16 priority levels.
 */
#define GIC_PRI_LOWEST     	0xf0
#define GIC_PRI_IRQ        	0xa0
#define GIC_PRI_IPI        	0x90 /* IPIs must preempt normal interrupts */
#define GIC_PRI_HIGHEST    	0x80 /* Higher priorities belong to Secure-World */
#define GIC_PRI_TO_GUEST(pri) 	(pri >> 3) /* GICH_LR and GICH_VMCR only support
                                            5 bits for guest irq priority */

struct gicv2_context {
    uint32_t hcr;      // Hypervisor Control Register, GICH_HCR
					   // 包含关于 virtual cpu interface 的一些控制位
    uint32_t vmcr;     // virtual machine control register
					   // alias of GICV_CTLR，一些权限控制位
    uint32_t apr;      //  Active Priorities Register, GICH_APR，32 bits
					      // 可以看做是当前优先级，其值由最近 acked 中断优先级高 5 位决定
						  // 如最近 acked 中断优先级高 5 位是 30，那么 GICH_APR[30] = 1
    uint32_t lr[64];   // lr 寄存器，存放发生虚拟中断的一些信息
};

struct gich_lr {
	uint32_t vid : 10;  // virq 中断号

	uint32_t pid : 10;	// 此 field 根据 hw 值不同而不同
						// hw=1，表示此虚拟中断关联了一个物理中断，此 pid 为实际的 physical irq 中断号
						// hw=0，bit19表示是否 signal eoi，给 maintenance interrupt 使用，不做讨论
								 //bit12-10，如果这是一个 sgi 中断，即 virtual interrupt id < 15，那么此位域表示 requesting cpu id

	uint32_t resv : 3;  //保留

	uint32_t pr : 5;	//该virtual integrrupt 的优先级

	uint32_t state : 2; //指示该中断的状态，invalid、pending、active、pending and active

	uint32_t grp1 : 1;	// 表示该 virtual integrrupt 是否是 group 1 virtual integrrupt
						// 0 表示这是一个 group 0 virtual interrupt，表示安全虚拟中断，可配置是按照 virq 还是 vfiq 发送给 vcpu
						// 1 表示这是一个 group 1 virtual interrupt，表示非安全虚拟中断，该中断以 virq 的形式触发，而不是 vfiq

	uint32_t hw : 1;    // 该虚拟中断是否关联了一个硬件物理中断
						// 0 表示否，这是 triggered in software，当 deactivated 的时候不会通知 distributor
						// 1 表示是，那么 deactivate 这个虚拟中断也会向对应的物理中断也执行 deactivate 操作
						// 而具体的 deactivate 操作，如果 gicv_ctlr.eoimode=0，写 gicv_eoir 寄存器表示 drop priority 和 deactive 操作同时进行 
						// 如果 gicv_ctlr.eoimode=1，写 gicv_eoir 寄存器表示 drop priority，写 GICV_DIR 表示 deactive
};

#endif
