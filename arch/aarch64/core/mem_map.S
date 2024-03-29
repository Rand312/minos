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
#include <asm/asm_marco.S>
#include "stage1.h"
#include <asm/aarch64_reg.h>

	/*
	 * map the code memory VA->PA, if need to using
	 * dcache need to enable the MMU, first clear
	 * the page table, below is the var defination
	 * Note, this function will call memset, and memset
	 * will use x0 - x4, so need pay attention for x0-x4
	 * if there some value saved in these register
	 */
page_table	.req	x24
ttb0_pgd	.req	x20
ttb0_pud	.req	x21
ttb0_pmd	.req	x22

vaddr		.req	x5
paddr		.req	x6
size		.req	x7
pte_attr	.req	x8

tmp_const	.req	x9
pud_tmp		.req	x10
pmd_tmp		.req	x12
tmp		.req	x13
pte_value	.req	x14
pte_index	.req	x15
entry_size	.req	x16
entry_align	.req	x17
entry_mask	.req	x18
pagetable_base	.req	x23		// store the pagetable for page allocation

	.section __start_up, "ax"
	.balign 4

	.global	map_boot_mem

.macro asm_get_boot_page reg
	mov	\reg, pagetable_base
	add	pagetable_base, pagetable_base, #4096
.endm

#define HOST_TABLE_DES	(S1_DES_TABLE)

map_boot_mem:
	/* save the lr register */
	mov	x26, x30

	/* get the base address of free memory */
	adr	pagetable_base, minos_stack_top    //获取 minos_stack_top 这个符号的地址，赋值给 pagetable_base
	ldr	pagetable_base, [pagetable_base]   //获取真正的 pagetable 地址

	/* kernel pgd is defined in lds */
	// 对pagetable做memset操作
	mov	x1, #0          //memset 第一个(从零开始)参数
	mov	x2, #4096       //memset 第二个参数
	ldr	page_table, = __stage1_page_table  // 获取 __stage1_page_table 的绝对地址，链接后的地址，如果该标号不在本文件中定义，则留下一个重定位符号
	asm_vtop page_table
	mov	x0, page_table
	bl	memset
	// boot memory must at 0 - 4GB space, here will
	// alloc all the 4GB memory's PUD
	bl	build_page_table

	// map the reserve memory as rw
	adr	vaddr, minos_start
	ldr	vaddr, [vaddr]
	ldr	tmp, =__code_start
	asm_vtop tmp
	sub	size, tmp, vaddr
	cbz	size, __map_code_section
	mov	paddr, vaddr
	ldr	pte_attr, =BOOTMEM_DATA_ATTR
	bl	build_normal_pte_table

	// map the code section rx
__map_code_section:
	ldr	vaddr, =__code_start
	ldr	tmp, =__code_end
	sub	size, tmp, vaddr
	asm_vtop vaddr
	mov	paddr, vaddr
	ldr	pte_attr, =BOOTMEM_CODE_ATTR
	bl	build_normal_pte_table

	// map the init data section rwx, data section will
	// be freed after system is bootup
	ldr	vaddr, =__init_start
	ldr	tmp, =__init_end
	sub	size, tmp, vaddr
	asm_vtop vaddr
	mov	paddr, vaddr
	ldr	pte_attr, =BOOTMEM_INIT_ATTR
	bl	build_normal_pte_table

	// map the data section
	ldr	vaddr, =__data_start
	ldr	tmp, =__data_end
	sub	size, tmp, vaddr
	asm_vtop vaddr
	mov	paddr, vaddr
	ldr	pte_attr, =BOOTMEM_DATA_ATTR
	bl	build_normal_pte_table

	// map the RO data section like symbol and string
	// RO section is the last section in the dts, so the
	// the range is from __rodata_start to minos_bootmem_base
	ldr	vaddr, =__rodata_start
	asm_vtop vaddr
	adr	tmp, minos_bootmem_base
	ldr	tmp, [tmp]
	sub	size, tmp, vaddr
	mov	paddr, vaddr
	ldr	pte_attr, =BOOTMEM_DATA_RO_ATTR
	bl	build_normal_pte_table

	// map the left 4K pages
	adr	vaddr, minos_bootmem_base
	ldr	vaddr, [vaddr]
	mov	tmp, vaddr
	ldr	entry_mask, =0x1fffff
	add	tmp, tmp, entry_mask
	mvn	entry_align, entry_mask
	and	tmp, tmp, entry_align
	mov	paddr, vaddr
	sub	size, tmp, vaddr
	ldr	pte_attr, =BOOTMEM_DATA_ATTR
	bl	build_normal_pte_table

	// map the UART memory for early log rw-device
	ldr	vaddr, =CONFIG_UART_BASE
	mov	paddr, vaddr
	ldr	size, =CONFIG_UART_IO_SIZE
	ldr	pte_attr, =BOOTMEM_IO_ATTR
	bl	build_io_pte_table

	// update the pagetable base
	adr	x0, minos_end
	str	pagetable_base, [x0]

	ret	x26

build_io_pte_table:
	mov	x25, x30

	ldr	entry_size, =0x1000
	ldr	entry_mask, =0xfff
	ldr	entry_align, =0xfffffffffffff000

	// alloc one page to map 2M IO pmd
	mov	x0, pagetable_base
	add	pagetable_base, pagetable_base, #4096
	mov	pmd_tmp, x0
	mov	x1, #0
	mov	x2, #4096
	bl	memset

	// if the memory region is not in a 2M range ?
	add	x1, vaddr, size
	add	x1, x1, entry_mask
	and	x1, x1, entry_align

	and	vaddr, vaddr, entry_align
	and	paddr, paddr, entry_align
	sub	size, x1, vaddr

	ubfx	x0, vaddr, #21, #11
	ldr	x1, =HOST_TABLE_DES
	orr	x1, pmd_tmp, x1
	str	x1, [ttb0_pud, x0, lsl #3]

	ldr	entry_align, =0x1fffff
	and	x2, vaddr, entry_align
	lsr	x2, x2, #12
	orr	paddr, paddr, pte_attr

loop_io_pte:
	str	paddr, [pmd_tmp, x2, lsl #3]
	sub	size, size, entry_size
	add	paddr, paddr, entry_size
	add	x2, x2, #1
	cbnz	size, loop_io_pte
	ret	x25

build_normal_pte_table:
	ldr	entry_size, =0x1000
	ldr	entry_mask, =0xfff
	ldr	entry_align, =0xfffffffffffff000

	// the va and pa must page align, so the info
	// from lds must correct
	and	vaddr, vaddr, entry_align
	and	paddr, paddr, entry_align
	and	size, size, entry_align

	// get the va offset in bootmem
	adr	x0, minos_start
	ldr	x0, [x0]
	sub	x0, vaddr, x0
	ubfx	pte_index, x0, #12, #20  //提取x0寄存器中的位字段，从第12位开始，长度为20位，并将结果存储在pte_index寄存器中
	mov	pmd_tmp, ttb0_pmd
	add	pmd_tmp, pmd_tmp, pte_index, lsl #3
	// 通过bic paddr, paddr, #0xffff000000000000对paddr进行按位清零操作
	bic	paddr, paddr, entry_mask
	bic	paddr, paddr, #0xffff000000000000
	orr	paddr, paddr, pte_attr

loop_normal_pte:
	cbz	size, exit_loop
	str	paddr, [pmd_tmp]
	sub	size, size, entry_size
	add	pmd_tmp, pmd_tmp, #8
	add	paddr, paddr, entry_size
	b	loop_normal_pte
exit_loop:
	ret

build_page_table:
	mov	x25, x30

	// map first 4GB for minos boot memory, here
	// need 4 pages
	// 对 4 页 pud 清零
	mov	x3, #4
	mov	ttb0_pud, pagetable_base
	ldr	x2, =(4096 << 2)
	add	pagetable_base, pagetable_base, x2
	mov	x0, ttb0_pud
	mov	x1, #0
	bl	memset

	mov	vaddr, #0x0
	mov	entry_size, #4
	mov	tmp, ttb0_pud
	mov	pte_index, 0
	ldr	x1, =HOST_TABLE_DES
loop_pud:
	// 将 pud 的地址记录在 pgd 中
	// 0x4007 a003 0x4007 b003 0x4007 c003 0x4007 d003
	orr	pte_value, tmp, x1
	str	pte_value, [page_table, pte_index, lsl #3]
	add	pte_index, pte_index, #1
	add	tmp, tmp, #0x1000
	sub	entry_size, entry_size, #1
	cbnz	entry_size, loop_pud

	// count how many memory is mapped as 4K page
	// other memory will mapped as PMD block
	adr	vaddr, minos_bootmem_base
	ldr	vaddr, [vaddr]   //0x4007 2000
	mov	tmp, vaddr
	ldr	entry_mask, =0x1fffff
	add	tmp, tmp, entry_mask
	mvn	entry_align, entry_mask
	and	tmp, tmp, entry_align   //这里得到以2M向上对齐的 minos_bootmem_base 0x2000 0000
	adr	pte_value, minos_start
	ldr	pte_value, [pte_value]

	// size record the 4K page size
	// tmp_const record the 2M block start address
	mov	tmp_const, tmp
	sub	size, tmp, pte_value   // 从 minos_start 到 以向上2M对齐的 minos_bootmem_base

	lsr	x3, size, #21  // 计算这个大小里面有几个 pmd(2M)
	lsl	x2, x3, #12  // 这几个 pmd 页表的大小

	mov	ttb0_pmd, pagetable_base
	add	pagetable_base, pagetable_base, x2
	mov	x0, ttb0_pmd
	mov	x1, #0
	bl	memset

	// minos_start address 2M align minos_start
	// will set at boot stage correctly
	adr	vaddr, minos_start
	ldr	vaddr, [vaddr]

	lsr	pte_index, vaddr, #21  //0x200
	mov	tmp, ttb0_pmd
	ldr	x1, =HOST_TABLE_DES
loop_pmd:
	orr	pte_value, tmp, x1
	str	pte_value, [ttb0_pud, pte_index, lsl #3]
	add	pte_index, pte_index, #1
	add	tmp, tmp, #4096
	sub	x3, x3, #1
	cbnz	x3, loop_pmd

	// continue map the pmd block memory
	ldr	x2, =CONFIG_MINOS_RAM_SIZE
	sub	size, x2, size
	lsr	size, size, #21
	ldr	entry_mask, =0x200000

	mov	paddr, tmp_const
	ldr	pte_attr, =BOOTMEM_DATA_BLK_ATTR
loop_pmd_blk:
	orr	pte_value, paddr, pte_attr
	str	pte_value, [ttb0_pud, pte_index, lsl #3]
	add	pte_index, pte_index, #1
	add	paddr, paddr, entry_mask
	sub	size, size, #1
	cbnz	size, loop_pmd_blk

	ret	x25
