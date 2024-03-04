/*
 * Copyright (C) 2018 Min Le (lemin9538@gmail.com)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <asm/aarch64_common.h>
#include <config/config.h>
#include <asm/asm-offset.h>
#include <asm/asm_marco.S>
#include <asm/aarch64_reg.h>

	.section __start_up, "ax"
	.balign 4

.macro clear_ttbr0
#ifdef CONFIG_VIRT
	tlbi	alle2   // invalid e2 all tlb entries
#else
	msr     ARM64_TTBR0, xzr     //xzr 寄存器为 0 值寄存器
	tlbi	vmalle1   // invalid all e1 tlb entries
#endif
.endm

	// current task is store in the x18
.macro set_percpu_idle_task tsk, tsk_size, cpuid
	ldr	\tsk, =idle_tasks
	ldr	\tsk_size, =TASK_SIZE
	mul	\tsk_size, \tsk_size, \cpuid
	add	\tsk, \tsk, \tsk_size
	mov	x18, \tsk
.endm

	// TPIDR_ELx will store the pcpu data
.macro set_percpu_pcpu pcpu, pcpu_size, cpuid
	ldr	\pcpu, =pcpus
	ldr	\pcpu_size, =PCPU_SIZE
	mul	\pcpu_size, \pcpu_size, \cpuid
	add	\pcpu, \pcpu, \pcpu_size
	msr	ARM64_TPIDR, \pcpu
	asm_vtop \pcpu
	str	x19, [\pcpu, #PCPU_ID_OFFSET]
.endm

	.global _start
	.type _start, "function"
_start:
	/* interrupt disabled mmu/dcache/icache off */
	msr	daifset, #2
	b	do_start
	/*为了不修改u-boot，直接使用u-boot的booti命令，需要在起始地址偏移为8字节的地方加上image header*/
	.quad   0				/* Image load offset from start of RAM */
        .quad   __code_end - _start		/* reserved */
        .quad   8				/* kernel flags */
        .quad   0				/* reserved */
        .quad   0				/* reserved */
        .quad   0				/* reserved */
        .byte   0x41				/* Magic number, "ARM\x64" */
        .byte   0x52
        .byte   0x4d
        .byte   0x64
        .long   0x0

do_start:
	mov	x27, x0				// save the dtb blob to x27

	// see which level we are now, minos currently can
	// support running on EL1 and EL2 but can not run
	// on EL3.
; Current Exception level.
; 0b00 EL0.
; 0b01 EL1.
; 0b10 EL2.
; 0b11 EL3
	mrs	x0, CurrentEl
	mov	x1, x0, lsr #2  // x0右移2位，结果存放到x1
	and	x1, x1, #3  // 结果与 0b11/EL3 相与

	// can not run on EL3.
	cmp	x1, #3   
	b.eq	minos_panic  // 表示当前处于 EL3

	mov	x26, #0   // 将 CurrentEl 存放到 x26
	cmp	x1, #2 // 与 0b10/EL2 比较

#ifdef CONFIG_VIRT  // 如果开启了虚拟化功能，那么此时应该处于 EL2
	b.ne	minos_panic  // 如果不是，panic

	mov	x0, 0  
	msr	HCR_EL2, x0  // HCR_EL2 寄存器设置为 0
	isb
#else
	// if current EL is not EL2 then jump to EL1
	// directly, othewise set 1 to x26 indicate that
	// need to jump to EL1
	b.ne	minos_os_start
	mov	x26, #1

	mov	x0, 0
	msr	HCR_EL2, x0
	isb
#endif // CONFIG_VIRT

	// init the EL2 env
	mrs	x0, midr_el1
	mrs	x1, mpidr_el1
	msr	vpidr_el2, x0
	msr	vmpidr_el2, x1

	/*
	 * neither EL3 nor EL2 trap floating point or
	 * accesses to CPACR
	 */
	// 不要 trap 访问 the Advanced SIMD and floating-point registers 的指令
	ldr	x0, =0x300000
	msr	CPTR_EL2, x0
	// 将 x31/zero register/也就是0 的值存放到 VTTBR_EL2
	msr	VTTBR_EL2, xzr
	dsb	sy
	isb

	cmp	x26, #1  // 前面将 x26 设置成了 0，这里应该是不相等
	b.ne	minos_os_start // 不等时跳转到 minos_os_start

	// drop to EL1
	mov	x1, #15
	msr	ICC_SRE_EL1, x1

	mrs	x1, HCR_EL2
	mov	x2, #HCR_EL2_RW
	orr	x2, x2, x1
	msr	HCR_EL2, x2
	isb

	msr	CPTR_EL2, xzr
	mov	x1, #0
	msr	SCTLR_EL2, x1

	mov	x1, #3
	msr	CNTHCTL_EL2, x1
	isb

drop_to_el1:
	adr	x1, minos_os_start
	msr	ELR_EL2, x1
	mov	x1, #(AARCH64_SPSR_EL1h | AARCH64_SPSR_F | AARCH64_SPSR_I | AARCH64_SPSR_A)
	msr	SPSR_EL2, x1
	eret
	dsb	nsh
	isb

minos_os_start:
	// _start 的值为 0x4000 0000
	adr	x1, _start			// entry address must 4K align
	and	x0, x1, #0xfff
	cbnz	x0, minos_panic  // 如果 x0 不等于 0，panic

	// minos_start to __code_start is the reserve memory
	// for minos, and must 2M aligned.
	// minos_start 是一个全局变量，记录着 _start 的值
	ldr	x3, =0xffffffffffe00000  // 将常数 0xffffffffffe00000 加载到寄存器 x3 中
	and	x1, x1, x3   // 执行完此条指令后，x1 = 0x4000 0000 与 _start 一样
	adr	x2, minos_start  // 将标签 minos_start 的地址加载到寄存器 x2 中，为 0x4004 4000
	str	x1, [x2]  // 将 x1 的值 _start 写到 0x4004 4000 地址处

	// 调用函数 arch_raw_smp_processor_id，将返回值保存到寄存器 x0 中，用于保存当前的处理器 ID
	bl	arch_raw_smp_processor_id	// cpuid save to x19
	mov	x19, x0   // 此时寄存器的值为 0

	/* using current EL stack register */
	// 选择当前使用的栈，EL_x
	// 写 0 表使用 SP_EL0 的栈，写 1 表示使用 SP_EL1
	msr	spsel, #1 

	// elx_vectors 又是一个全局变量，为 vector 的起始地址
	ldr	x1, =elx_vectors
	msr	ARM64_VBAR, x1  // 设置异常向量表的地址

	/* enable Abort now for early system abort */
	msr	daifclr, #4  // enable 系统级别的错误 SError 中断
	isb

	/* invalid the dcache and flush the tlb */
	// 调用函数 inv_dcache_all，用于使 dcache 失效
	bl	inv_dcache_all
	dsb	sy
	isb

#ifdef CONFIG_VIRT
	tlbi	alle2  // 使得所有 el2 级别的 tlb invalid
#else
	tlbi	vmalle1 // 如果没有开启虚拟化，使得 EL1 级别的 tlb 项目失效
#endif
	dsb	sy
	isb
	// #define ARM64_SCTLR_VALUE	0x30c51878
	ldr	x1, =ARM64_SCTLR_VALUE 
	msr	ARM64_SCTLR, x1  // 将这个值写入 SCTLR 寄存器
	dsb	nsh
	isb

	/* setup the el2 page table */
	ldr	x1, = __stage1_page_table  // 获取 hyp pagetable
	asm_vtop x1   // 空
	msr     ARM64_TTBR0, x1  // 将这页表地址赋值给 TTBR0_EL2
	msr     ARM64_TTBR1, x1
	dsb	nsh
	isb

	/*
	 * 0xff440c0400
	 * MT_DEVICE_NGNRNE	0
	 * MT_DEVICE_NGNRE	1
	 * MT_DEVICE_GRE	2
	 * MT_NORMAL_NC		3
	 * MT_NORMAL		4
	 * 0x00 - MT_DEVICE_NGNRNE
	 * 0x04 - MT_DEVICE_NGNRE
	 * 0x0c - MT_DEVICE_GRE
	 * 0x44 - MT_NORMAL_NC
	 * 0xff - MT_NORMAL
	 * 0xbb - MT_NORMAL_WT
	 */
	ldr	x1, =0xbbff440c0400
	msr	ARM64_MAIR, x1  // 设置 MAIR_EL2 Memory Attribute Indirection Register

	/* get the physical address range */
	//  AArch64 Memory Model Feature Register 0
	mrs	x0, ID_AA64MMFR0_EL1   // 0x1122
	and	x0, x0, #0xf  // Physical Address range supported
					  // 值为 0x2，表示 40 bits, 1TB
#if defined(CONFIG_VIRT)
	mov	x2, x0, lsl #16   // 将 x0 的值左移 16 位，然后存储到 x2 中
	ldr	x3, =0xfffffffffff8ffff
#else
	mov	x2, x0, lsl #32
	ldr	x3, =0xfffffff8ffffffff
#endif
	// TCR_EL2, Translation Control Register
	ldr	x1, =ARM64_TCR_VALUE		// load the value of TCR.  0x3519
	and	x1, x1, x3			// update the IPA/PA for TCR_ELx.  0x3519
	orr	x1, x1, x2   // 0x23519

	msr     ARM64_TCR, x1			// set the TCR_ELx.
	dsb	nsh
	isb

	// idle task is in Current_EL
	// 0x1c9
	mov	x1, #ARM64_SPSR_VALUE
	msr	ARM64_SPSR, x1

	// x19 里面存放的是 MPIDR_EL1 的值，如果为 0，表示为 Boost CPU
	// 否则为 application/secondary cpu，从这里开始走 secondary_start_up 来启动
	cbnz	x19, secondary_start_up

	ldr	x0, =__minos_end     // 获取 end 地址
	asm_vtop x0   // 当前配置下什么都没做
	// 
	adr	x1, minos_stack_top    // 0x4004 4010
	adr	x2, minos_bootmem_base   // 0x4004 4008
	adr	x3, minos_stack_bottom  // 0x4004 4018

	// store the bootmem base
	// 将 __minos_end 进行向上取整(4096)，作为 boot mem 的起始地址，然后将该值存放到 minos_bootmem_base
	add	x0, x0, #4095
	mov	x4, #4095  // 0xfff
	mvn	x5, x4  // 0xffff ffff ffff f000
	and	x0, x0, x5
	str	x0, [x2]

	// store the minos stack bottom
	str	x0, [x3]  // boot mem 的起始地址也是栈底

	// store the minos stack top
	mov	x4, #CONFIG_TASK_STACK_SIZE  // 8K 大小
	mov	x5, #CONFIG_NR_CPUS   // CPU 个数
	mul	x5, x4, x5  // 8K * CONFIG_NR_CPUS  // 0x8000
	add	x0, x0, x5  // 向上增加 0x8000
	str	x0, [x1]  // 将该值存储到 minos_stack_bottom

	sub	x0, x0, x19, lsl #CONFIG_TASK_STACK_SHIFT
	asm_ptov x0
	mov	sp, x0

	ldr	x0, =__bss_start
	asm_vtop x0
	mov	x1, #0
	ldr	x2, =__bss_end
	asm_vtop x2
	sub	x2, x2, x0
	bl	memset

	ldr	x0, =__percpu_start
	asm_vtop x0
	mov	x1, #0
	ldr	x2, =__percpu_end
	asm_vtop x2
	sub	x2, x2, x0
	bl	memset

	// map the boot memory when booting
	bl	map_boot_mem
	dsb	ishst
	isb

	// current task is store in the x18
	// x18 will store the current task pointer
	set_percpu_idle_task x0, x1, x19

	// TPIDR_ELx will store the pcpu data
	set_percpu_pcpu x0, x1, x19

	ldr	x26, =mmu_on

	// enable the mmu and disable the aligment check
	mrs	x1, ARM64_SCTLR
	orr	x1, x1, #SCTLR_ELx_M
	orr	x1, x1, #SCTLR_ELx_C
	orr	x1, x1, #SCTLR_ELx_I
	bic	x1, x1, #SCTLR_ELx_SA
	bic	x1, x1, #SCTLR_ELx_A
	msr	ARM64_SCTLR, x1
	dsb	sy
	isb

	br	x26

mmu_on:
	ic	ialluis
	dsb	sy
	isb

	clear_ttbr0

	mov	x0, x27		// restore the dtb address.
	bl	arch_main	// never return.
dead_loop:
	b	dead_loop

secondary_start_up:
	// setup the idle task stack
	adr	x0, minos_stack_top
	ldr	x0, [x0]
	sub	x0, x0, x19, lsl #CONFIG_TASK_STACK_SHIFT
	asm_ptov x0
	mov	sp, x0

	// current task is store in the x18
	// x18 will store the current task pointer
	set_percpu_idle_task x0, x1, x19

	// TPIDR_ELx will store the pcpu data
	set_percpu_pcpu x0, x1, x19

	ldr	x1, =ARM64_SCTLR_VALUE
	msr	ARM64_SCTLR, x1
	isb

	ldr     x26, =mmu_on_secondary

	// enable the dcache and the icache
	mrs	x1, ARM64_SCTLR
	orr	x1, x1, #SCTLR_ELx_C
	orr	x1, x1, #SCTLR_ELx_I
	orr	x1, x1, #SCTLR_ELx_M
	bic	x1, x1, #SCTLR_ELx_SA
	bic	x1, x1, #SCTLR_ELx_A
	msr	ARM64_SCTLR, x1
	dsb	sy
	isb

	br	x26

mmu_on_secondary:
	ic	ialluis
	dsb	sy
	isb

	clear_ttbr0

	ldr	x1, =__smp_affinity_id
	add	x1, x1, x19, lsl #3
	mrs	x2, MPIDR_EL1
	ldr	x4, =0x000000ff00ffffff
	and	x2, x2, x4
	str	x2, [x1]
	dsb	sy

	/* here wait for boot cpu finish tht init work */
	/* pass the cpuid to the boot_secondary */
	mov	x0, x19
	bl	boot_secondary

minos_panic:
	b	minos_panic

	.data
	.global minos_start
	.global minos_bootmem_base
	.global minos_stack_top
	.global minos_stack_bottom
	.global minos_end
	.balignl 16, 0xdeadbeef

minos_start:		.quad	0x0
minos_bootmem_base:	.quad	0x0
minos_stack_top:	.quad	0x0
minos_stack_bottom:	.quad	0x0
minos_end:		.quad	0x0
