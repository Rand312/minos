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
#include <asm/asm_marco.S>
#include <config/config.h>

	.global arch_raw_smp_processor_id
	.global arch_get_fp
	.global arch_get_lr
	.global arch_get_sp
	.global smc_call
	.global hvc_call
	.global aarch64_task_exit

func arch_raw_smp_processor_id
	mrs 	x0, MPIDR_EL1
	ldr	x4, =(1 << 24)
	and	x5, x0, x4
	cbnz	x5, __shift_mpidr
	// 从 bit0 开始提取 8 位，放入 x1
	ubfx    x1, x0, #MPIDR_EL1_AFF0_LSB, #MPIDR_EL1_AFF_WIDTH  
	// 从 bit8 开始提取 8 位，放入 x2
	ubfx    x2, x0, #MPIDR_EL1_AFF1_LSB, #MPIDR_EL1_AFF_WIDTH
	b	__out
__shift_mpidr:
	ubfx    x1, x0, #MPIDR_EL1_AFF1_LSB, #MPIDR_EL1_AFF_WIDTH
	ubfx    x2, x0, #MPIDR_EL1_AFF2_LSB, #MPIDR_EL1_AFF_WIDTH
__out:
	mov	x3, #CONFIG_NR_CPUS_CLUSTER0
	mul	x2, x2, x3
	add	x0, x2, x1
	dsb	sy
	ret
endfunc arch_raw_smp_processor_id

func arch_get_fp
	mov	x0, x29
	ret
endfunc arch_get_fp

func arch_get_lr
	mov	x0, x30
	ret
endfunc arch_get_lr

func arch_get_sp
	mov	x0, sp
	ret
endfunc arch_get_sp

func smc_call
	smc	#0
	ldr	x4, [sp]
	stp	x0, x1, [x4, #0]
	stp	x2, x3, [x4, #16]
	ret
endfunc smc_call

func hvc_call
	hvc	#0
	ldr	x4, [sp]
	stp	x0, x1, [x4, #0]
	stp	x2, x3, [x4, #16]
	ret
endfunc hvc_call

func aarch64_task_exit
	mov	x0, x0
	bl	task_exit
1:
	b	1b
endfunc aarch64_task_exit
