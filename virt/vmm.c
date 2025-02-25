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

#include <minos/minos.h>
#include <virt/vm.h>
#include <virt/iommu.h>
#include <minos/arch.h>

#define VM_IPA_SIZE (1UL << 40)

// block 集合，块内存池
struct block_section {
	// 该块内存池的起始地址，（因为最开始这片内存池是连续的)
	unsigned long start;  
	// 该块内存池大小
	unsigned long size;
	unsigned long end;
	unsigned long free_blocks;
	unsigned long total_blocks;
	unsigned long current_index;
	unsigned long *bitmap;
	struct block_section *next;
};

static struct block_section *bs_head;
static DEFINE_SPIN_LOCK(bs_lock);
static unsigned long free_blocks;
 
#define mm_to_vm(__mm) container_of((__mm), struct vm, mm)
#define VMA_SIZE(vma) ((vma)->end - (vma)->start)

// 对 guest 创建 mapping，vir 映射到 phy，映射大小为 size，标志为 flags
// 是 stage2 层次的映射
static int __create_guest_mapping(struct mm_struct *mm, virt_addr_t vir,
		phy_addr_t phy, size_t size, unsigned long flags)
{
	struct vm *vm = mm_to_vm(mm);
	unsigned long tmp;
	int ret;

	tmp = BALIGN(vir + size, PAGE_SIZE);
	vir = ALIGN(vir, PAGE_SIZE);
	phy = ALIGN(phy, PAGE_SIZE);
	size = tmp - vir;

	pr_debug("map [x%x 0x%x] to [0x%x 0x%x] vm-%d\n",
			vir, vir + size, phy, phy + size, vm->vmid);
	ret = arch_guest_map(mm, vir, vir + size, phy, flags);
	if (!ret)
		ret = iommu_iotlb_flush_all(vm);

	return ret;
}

int create_guest_mapping(struct mm_struct *mm, virt_addr_t vir,
		phy_addr_t phy, size_t size, unsigned long flags)
{
	int ret;

	spin_lock(&mm->lock);
	ret = __create_guest_mapping(mm, vir, phy, size, flags);
	spin_unlock(&mm->lock);

	return ret;
}

static int __destroy_guest_mapping(struct mm_struct *mm,
		unsigned long vir, size_t size)
{
	unsigned long end;
	int ret;

	if (!IS_PAGE_ALIGN(vir) || !IS_PAGE_ALIGN(size)) {
		pr_warn("WARN: destroy guest mapping [0x%x 0x%x]\n",
				vir, vir + size);
		end = PAGE_BALIGN(vir + size);
		vir = PAGE_ALIGN(vir);
		size = end - vir;
	}

	ret = arch_guest_unmap(mm, vir, vir + size);
	if (!ret)
		ret = iommu_iotlb_flush_all(mm_to_vm(mm));

	return ret;
}

int destroy_guest_mapping(struct mm_struct *mm, unsigned long vir, size_t size)
{
	int ret;

	spin_lock(&mm->lock);
	ret = __destroy_guest_mapping(mm, vir, size);
	spin_unlock(&mm->lock);

	return ret;
}

// 分配一个 vmm_area 结构体，记录 base、size 信息，只是记录信息，没有实际的内存分配
static struct vmm_area *__alloc_vmm_area_entry(unsigned long base, size_t size)
{
	struct vmm_area *va;

	va = zalloc(sizeof(struct vmm_area));
	if (!va)
		return NULL;

	va->start = base;
	// -1(0xfffffffffff)，表示未分配映射实际的物理内存
	va->pstart = BAD_ADDRESS;
	va->end = base + size;
	va->flags = 0;

	return va;
}

// 将新 vmm_area 加入到 mm->list 链表当中去
static int __add_free_vmm_area(struct mm_struct *mm, struct vmm_area *area)
{
	struct vmm_area *tmp, *next, *va = area;
	size_t size;

	/*
	 * indicate it not inserted to the free list
	 */
	va->list.next = NULL;
	size = va->end - va->start;
	va->flags = 0;
	va->vmid = 0;
	va->pstart = 0;
repeat:
	/*
	 * check whether this two vmm_area can merged to one
	 * vmm_area and do the action
	 */
	// 遍历 mm 中所有的 vmm_area 结构体
	list_for_each_entry_safe(tmp, next, &mm->vmm_area_free, list) {
		if (va->start == tmp->end) {
			va->start = tmp->start;
			list_del(&tmp->list);
			free(tmp);
			goto repeat;
		}

		if (va->end == tmp->start) {
			va->end = tmp->end;
			list_del(&tmp->list);
			free(tmp);
			goto repeat;
		}
		// vmm_area_free 按照从小到大的顺序排列
		if (size <= (tmp->end - tmp->start)) {
			list_insert_before(&tmp->list, &va->list);
			break;
		}
	}
	// 走到这里说明要插入的 area 是最大的，上面循环并未插入，这里补充将其挂入链表最后
	if (va->list.next == NULL)
		list_add_tail(&mm->vmm_area_free, &va->list);

	return 0;
}

// 释放该 vma 区域中的所有 mem_block
static void inline release_vmm_area_bk(struct vmm_area *va)
{
	struct mem_block *block = va->b_head, *tmp;

	// 遍历该 vma 中的所有 mem_block，然后释放
	while (block != NULL) {
		tmp = block->next;
		block->next = NULL;
		vmm_free_memblock(block);
		block = tmp;
	}

	va->b_head = NULL;
}

// 释放整个 vma 区域的内存
static void release_vmm_area_memory(struct vmm_area *va)
{
	/*
	 * can not free the physical memory when the memory
	 * is not belong to this vmm_area, this means the va
	 * is shareded with other vmm area, not the owner of
	 * it.
	 */
	// 如果该 vma 区域的内存是共享的，不能释放，直接返回
	if (va->flags & __VM_SHARED)
		return;

	// 
	switch (va->flags & VM_MAP_TYPE_MASK) {
	case VM_MAP_PT:
		break;
	// 如果该 vma 区域的内存以 mem_block 的形式存在，调用 release_vmm_area_bk 释放 vma 区域所有 mem_block
	case VM_MAP_BK:
		release_vmm_area_bk(va);
		break;
	
	default:
		if (va->pstart != BAD_ADDRESS) {
			// 释放共享页？？？？？？？
			if (va->flags & __VM_SHMEM)
				free_shmem((void *)va->pstart);
			// 释放普通的页面，只释放一次？ 这里就是说 一个 vmm_area 结构也就对应这一个 struct page???? 然后里面可能记录了连续的多页？？？？
			else
				free_pages((void *)va->pstart);
			va->pstart = BAD_ADDRESS;
		}
		break;
	}
}

// 释放 vma 内存
int release_vmm_area(struct mm_struct *mm, struct vmm_area *va)
{	
	// 释放内存
	release_vmm_area_memory(va);
	spin_lock(&mm->lock);
	// 将该 vma 结构体从 mm->vmm_area_used 链表中移除
	list_del(&va->list);
	// 将该 vma 结构体挂入 vmm_area_free 链表
	__add_free_vmm_area(mm, va);
	spin_unlock(&mm->lock);

	return 0;
}


// 创建 stage2 映射
static int vmm_area_map_ln(struct mm_struct *mm, struct vmm_area *va)
{
	return __create_guest_mapping(mm, va->start,
			va->pstart, VMA_SIZE(va), va->flags);
}

// 创建 stage2 block 映射
static int vmm_area_map_bk(struct mm_struct *mm, struct vmm_area *va)
{
	struct mem_block *block = va->b_head;;
	unsigned long base = va->start;
	unsigned long size = VMA_SIZE(va);
	int ret;

	// 遍历 vma_area 中的所有 block，建立映射
	while (block) {
		ret = __create_guest_mapping(mm, base, BFN2PHY(block->bfn),
				MEM_BLOCK_SIZE, va->flags | VM_HUGE | VM_GUEST);
		if (ret)
			return ret;

		base += MEM_BLOCK_SIZE;
		size -= MEM_BLOCK_SIZE;
		block = block->next;
	}

	ASSERT(size == 0);

	return 0;
}

// 对 vma_area 中的内存建立映射
int map_vmm_area(struct mm_struct *mm,
		struct vmm_area *va, unsigned long pbase)
{
	int ret;

	switch (va->flags & VM_MAP_TYPE_MASK) {
	case VM_MAP_PT:  // 建立直接映射
		va->pstart = va->start;
		ret = vmm_area_map_ln(mm, va);
		break;
	case VM_MAP_BK:
		ret = vmm_area_map_bk(mm, va);
		break;
	// create_hvm_shmem_map 的时候走 default
	default:
		va->pstart = pbase;
		ret = vmm_area_map_ln(mm, va);
		break;
	}

	return ret;
}

// split 参数中的 vma_area 结构体，建立新的 vmm_area 结构体，插入到 mm->vmm_area_used 链表
// 参数中的 vma，用剩下的，重新插入到 mm->vmm_area_free 链表
static struct vmm_area *__split_vmm_area(struct mm_struct *mm,
		struct vmm_area *vma, unsigned long base,
		unsigned long end, int flags)
{
	struct vmm_area *left = NULL, *right = NULL;
	size_t left_size, right_size;

	left_size = base - vma->start;
	right_size = vma->end - end;

	if (left_size == 0 && right_size == 0)
		goto out;

	if (left_size > 0) {
		left = __alloc_vmm_area_entry(vma->start, left_size);
		if (!left)
			return NULL;
		// split 之后插入到 vmm_area_free 链表之中
		list_add(&mm->vmm_area_free, &left->list);
	}

	if (right_size > 0) {
		right = __alloc_vmm_area_entry(end, right_size);
		if (!right)
			goto out_err_right;
		list_add(&mm->vmm_area_free, &right->list);
	}
out:
	vma->start = base;
	vma->end = end;
	vma->flags = flags;
	list_del(&vma->list);
	list_add_tail(&mm->vmm_area_used, &vma->list);

	return vma;

out_err_right:
	if (left) {
		list_del(&left->list);
		free(left);
	}
	return NULL;
}

// 从现有的 vma_area 中分割出来一部分内存
static struct vmm_area *__alloc_free_vmm_area(struct mm_struct *mm,
		struct vmm_area *vma, size_t size,
		unsigned long mask, int flags)
{
	unsigned long base, end;

	// mask 字节对齐
	base = (vma->start + mask) & ~mask;
	end = base + size;
	// 如果 base~end 没有在当前 vma 的区间范围之内
	if (!((base >= vma->start) && (end <= vma->end)))
		return NULL;
	
	// 从当前
	return __split_vmm_area(mm, vma, base, end, flags);
}

// 分配一个 vmm_area 
struct vmm_area *alloc_free_vmm_area(struct mm_struct *mm,
		size_t size, unsigned long mask, int flags)
{
	struct vmm_area *va;
	struct vmm_area *new = NULL;

	mask = (mask == BLOCK_MASK) ? BLOCK_MASK : PAGE_MASK;
	size = BALIGN(size, PAGE_SIZE);

	spin_lock(&mm->lock);
	// 遍历当前所有的 vmm_area 结构体
	list_for_each_entry(va, &mm->vmm_area_free, list) {
		// 如果当前 vmm_area 记录的内存区域不够内存分配，continue
		if ((va->end - va->start) < size)
			continue;
		
		// 从当前的 vmm_area 分割出一块内存，然后以 vmm_area 记录
		new = __alloc_free_vmm_area(mm, va, size, mask, flags);
		if (new)
			break;
	}
	spin_unlock(&mm->lock);

	return new;
}

// 从 mm->vmm_area_free 所有的 vmm_list 中，找一个合适的 vmm_area，从中切出一个 vmm_area，此 vmm_area 的 start 为 base，end 为 start+size
struct vmm_area *split_vmm_area(struct mm_struct *mm,
		unsigned long base, size_t size, int flags)
{
	unsigned long end = base + size;
	struct vmm_area *va, *out = NULL;

	if ((flags & VM_NORMAL) && (!IS_PAGE_ALIGN(base) || !IS_PAGE_ALIGN(size))) {
		pr_err("vm_area is not PAGE align 0x%p 0x%x\n",
				base, size);
		return NULL;
	}

	spin_lock(&mm->lock);
	// 遍历 vmm_area_free 中所有 vma 结构体
	list_for_each_entry(va, &mm->vmm_area_free, list) {
		// 如果 [base,end] < [start, end]，break
		if ((base >= va->start) && (end <= va->end)) {
			out = va;
			break;
		}
	}

	if (!out)
		goto exit;

	// split 参数中的 vmm_area 结构体，建立新的 vmm_area 结构体，插入到 mm->vmm_area_used 链表
	// 被分割的 vmm_area，其用剩下的，重新插入到 mm->vmm_area_free 链表
	out = __split_vmm_area(mm, out, base, end, flags);
exit:
	spin_unlock(&mm->lock);

	if (!out)
		pr_err("split vma [0x%lx 0x%lx] failed\n", base, end);

	return out;
}

// 请求分配一个 vmm_area，就是从现有的空闲 vmm_area 中切割
struct vmm_area *request_vmm_area(struct mm_struct *mm,
		unsigned long base, unsigned long pbase,
		size_t size, int flags)
{
	struct vmm_area *va;

	va = split_vmm_area(mm, base, size, flags);
	if (!va)
		return NULL;

	va->pstart = pbase;

	return va;
}

static void dump_vmm_areas(struct mm_struct *mm)
{
	struct vmm_area *va;

	pr_debug("***** free vmm areas *****\n");
	list_for_each_entry(va, &mm->vmm_area_free, list)
		pr_debug("[VA] 0x%p->0x%p\n", va->start, va->end);

	pr_debug("***** used vmm areas *****\n");
	list_for_each_entry(va, &mm->vmm_area_used, list)
		pr_debug("[VA] 0x%p->0x%p\n", va->start, va->end);
}

//将 vmid 为 vm->vmid 但是位于 vm0 的内存 归还给 vm0
// 释放 vmm_area 内存，这部分内存属于 vm（vmid 不是 vm0），但是位于（挂在）vm0 的链表上
static void release_vmm_area_in_vm0(struct vm *vm)
{
	struct vm *vm0 = get_host_vm();
	struct mm_struct *mm = &vm0->mm;
	struct vmm_area *va, *n;

	spin_lock(&mm->lock);
	// 遍历 vm0 正在使用的 vmm_area
	list_for_each_entry_safe(va, n, &mm->vmm_area_used, list) {
		// 如果不等于 vm->vmid，说明该 vmm_area 属于 vm0，continue，也就是要寻找不属于 vm0 的 vmm_area
		if (va->vmid != vm->vmid)
			continue;
		
		
		// 找到了，取消该 vmm_area 的 stage2 映射
		__destroy_guest_mapping(mm, va->start, VMA_SIZE(va));

		// 如果该 vma 不是共享的，释放掉相关页面
		if (!(va->flags & VM_SHARED))
			free_pages((void *)va->pstart);
		
		// 将该 vmm_area 从 vm0 的 vmm_area_used 链表中删除
		list_del(&va->list);
		// 将该 vmm_area 添加到 vm0 的 vmm_area_free 链表中
		__add_free_vmm_area(mm, va);
	}
	spin_unlock(&mm->lock);
}

// 取消 vmm_area 内存的映射
int unmap_vmm_area(struct mm_struct *mm, struct vmm_area *va)
{
	int ret;

	spin_lock(&mm->lock);
	ret = __destroy_guest_mapping(mm, va->start, VMA_SIZE(va));
	spin_unlock(&mm->lock);	

	return ret;
}

// 释放掉整个 vm 的内存
void release_vm_memory(struct vm *vm)
{
	struct mm_struct *mm = &vm->mm;
	struct vmm_area *va, *n;

	/*
	 * first unmap all the memory which maped to
	 * this VM. this will free the pages which used
	 * as the PAGE_TABLE, then free to the host.
	 */
	// 取消 vm 的内存映射
	destroy_guest_mapping(mm, 0, VM_IPA_SIZE);

	/*
	 * - release all the vmm_area and its memory
	 * - release the page table
	 * - set all the mm_struct to 0
	 * this function will not be called when vm is
	 * running, do not to require the lock
	 */
	// 释放掉所有 vmm_area 对应的内存
	list_for_each_entry_safe(va, n, &mm->vmm_area_used, list) {
		release_vmm_area_memory(va);
		list_del(&va->list);
		free(va);
	}

	list_for_each_entry_safe(va, n, &mm->vmm_area_free, list) {
		list_del(&va->list);
		free(va);
	}

	/* release the vm0's memory belong to this vm */
	// 释放 vm0 中的内存，但是这部分内存属于其他 vm
	release_vmm_area_in_vm0(vm);

	// 释放所有级别的页表内存，这里因为特殊设计，将所有 page 链起来，所以直接遍历链表释放相关内存即可，不用遍历页表然后释放
	free_pages((void *)mm->pgdp);
}

// 返回 ipa 地址
unsigned long create_hvm_shmem_map(struct vm *vm,
			unsigned long phy, uint32_t size)
{

	struct vm *vm0 = get_host_vm();
	struct vmm_area *va;

	// 从 vm0 中分配一个 vmm_area
	va = alloc_free_vmm_area(&vm0->mm, size, PAGE_MASK, VM_GUEST_SHMEM |
			VM_SHARED | VM_RW);
	if (!va)
		return BAD_ADDRESS;

	// 从 vm0 分配出来的 vmm_area 的 vmid 设置为 vmx->vmid
	va->vmid = vm->vmid;
	map_vmm_area(&vm0->mm, va, phy);

	return va->start;
}

// src 是 guest 中的一个 va，具体来说是 Linux 内核中的一个虚拟地址
// 此函数要从 guest Linux 内核中拷贝一些数据到 hypervisor
int copy_from_guest(void *target, void __guest *src, size_t size)
{
	unsigned long start = (unsigned long)src;
	size_t copy_size, left = size;
	unsigned long pa;
	int ret;

	while (left > 0) {
		copy_size = PAGE_BALIGN(start) - PAGE_ALIGN(start);
		if (copy_size == 0)
			copy_size = PAGE_SIZE;
		if (copy_size > left)
			copy_size = left;
		
		// 将 gva 转换为 pa，经过了 stage1 和 stage2 的转换
		pa = guest_va_to_pa(start, 1);
		// 创建直接映射，将 pa 物理地址映射为在 (hypervisor)EL2 能够访问的虚拟地址
		ret = create_host_mapping(PAGE_ALIGN(ptov(pa)),
				PAGE_ALIGN(pa), PAGE_SIZE, VM_RO);
		if (ret)
			return ret;
		
		// 拷贝数据
		memcpy(target, (void *)vtop(pa), copy_size);
		destroy_host_mapping(PAGE_ALIGN(ptov(pa)), PAGE_SIZE);

		target += copy_size;
		start += copy_size;
		left -= copy_size;
	}

	return 0;
}

// 通过 walk pagetable 来进行 stage2 的地址转换
// 将 ipa 转换为 pa
int translate_guest_ipa(struct mm_struct *mm,
		unsigned long offset, unsigned long *pa)
{
	int ret;

	spin_lock(&mm->lock);
	ret = arch_translate_guest_ipa(mm, offset, pa);
	spin_unlock(&mm->lock);

	return ret;
}

// mm 为 vmx，即 guest_vm->mm
// hvm_mmap_base，vm0 的 vmm_area->start
// offset，guest_vm base addr

// do_vm_mmap(&vm->mm, va->start, offset, size);
static int do_vm_mmap(struct mm_struct *mm, unsigned long hvm_mmap_base,
		unsigned long offset, unsigned long size)
{
	struct vm *vm0 = get_host_vm();
	struct mm_struct *mm0 = &vm0->mm;
	unsigned long pa;
	int ret;

	if (!IS_BLOCK_ALIGN(offset) || !IS_BLOCK_ALIGN(hvm_mmap_base) ||
			!IS_BLOCK_ALIGN(size)) {
		pr_err("__vm_mmap fail not PMD align 0x%p 0x%p 0x%x\n",
				hvm_mmap_base, offset, size);
		return -EINVAL;
	}

	while (size > 0) {
		// 将 guest physical addr 转换成 physical addr
		ret = translate_guest_ipa(mm, offset, &pa);
		if (ret) {
			pr_err("addr 0x%x has not mapped in vm-%d\n", offset, vm0->vmid);
			return -EPERM;
		}

		// 创建该 vm 对于该段内存在 stage2 的映射关系
		ret = create_guest_mapping(mm0, hvm_mmap_base,
				pa, MEM_BLOCK_SIZE, VM_NORMAL | VM_RW);
		if (ret) {
			pr_err("%s failed\n", __func__);
			return ret;
		}

		hvm_mmap_base += MEM_BLOCK_SIZE;
		offset += MEM_BLOCK_SIZE;
		size -= MEM_BLOCK_SIZE;
	}

	return 0;
}

/*
 * map the guest vm memory space to vm0 to let vm0 can access
 * the memory space of the guest VM, this function can only
 * map the normal memory for the guest VM, will not map IO
 * memory
 *
 * offset - the base address need to be mapped
 * size - the size need to mapped
 */

// 为 [offset, offset+size) 这一段内存区域创建 stage2 映射
// 从后面的代码反向推理，offset 应该是一个 ipa 地址，MARK，待通过 Linux 验证
struct vmm_area *vm_mmap(struct vm *vm, unsigned long offset, size_t size)
{
	struct vm *vm0 = get_host_vm();
	struct vmm_area *va;
	int ret;

	/*
	 * allocate all the memory the GVM request but will not
	 * map all the memory, only map the memory which mvm request
	 * for linux, if it need use virtio then need to map all
	 * the memory, but for other os, may not require to map
	 * all the memory.
	 */
	va = alloc_free_vmm_area(&vm0->mm, size,
			BLOCK_MASK, VM_GUEST_NORMAL | VM_SHARED | VM_RW);
	if (!va)
		return 0;

	pr_info("%s start:0x%x size:0x%x\n", __func__, va->start, size);
	ret = do_vm_mmap(&vm->mm, va->start, offset, size);
	if (ret) {
		pr_err("map guest vm memory to vm0 failed\n");
		release_vmm_area(&vm0->mm, va);
		return NULL;
	}

	/* mark this vmm_area is for guest vm map */
	va->vmid = vm->vmid;

	return va;
}

// 从 block 中分配物理内存
static int __alloc_vm_memory(struct mm_struct *mm, struct vmm_area *va)
{
	int i, count;
	unsigned long base;
	struct mem_block *block;
	// 起始地址 2M 对齐
	base = ALIGN(va->start, MEM_BLOCK_SIZE);
	if (base != va->start) {
		pr_err("memory base is not mem_block align\n");
		return -EINVAL;
	}

	va->b_head = NULL;
	va->flags |= VM_MAP_BK;
	// 计算该 vmm_area 大小等于多少个 mem_block
	count = VMA_SIZE(va) >> MEM_BLOCK_SHIFT;

	/*
	 * here get all the memory block for the vm
	 * TBD: get contiueous memory or not contiueous ?
	 */
	// 这里分配所有 mem_block 结构体
	for (i = 0; i < count; i++) {
		block = vmm_alloc_memblock();
		if (!block)
			return -ENOMEM;

		// 头插法到 va->b_head 链表
		block->next = va->b_head;
		va->b_head = block;
	}

	return 0;
}

// 为 guest vm 分配和映射物理内存
int alloc_vm_memory(struct vm *vm)
{
	struct mm_struct *mm = &vm->mm;
	struct vmm_area *va;

	// 如果是刚创建 vm 时走到这里的话，
	// vmm_area_used 链表中应该只有一个 vma 结构，此结构是从整体的 ipa vma 中 split 下来的，见 guest_mm_init 函数流程
	list_for_each_entry(va, &mm->vmm_area_used, list) {
		if (!(va->flags & VM_NORMAL))
			continue;
		// 从 block 中分配内存
		if (__alloc_vm_memory(mm, va)) {
			pr_err("alloc memory for vm-%d failed\n", vm->vmid);
			goto out;
		}

		// 建立 stage2 映射
		if (map_vmm_area(mm, va, 0)) {
			pr_err("map memory for vm-%d failed\n", vm->vmid);
			goto out;
		}
	}

	return 0;
out:
	release_vm_memory(vm);
	return -ENOMEM;
}

// 创建 vm 的第一个 vmm_area
static void vmm_area_init(struct mm_struct *mm, int bit64)
{
	unsigned long base, size;
	struct vmm_area *va;

	/*
	 * the virtual memory space for a virtual machine:
	 * 64bit - 40bit (1TB) IPA address space.
	 * 32bit - 32bit (4GB) IPA address space. (Without LPAE)
	 * 32bit - TBD (with LPAE)
	 */
	if (bit64) {
		base = 0x0;
		size = (1UL << 40);
	} else {
#ifdef CONFIG_VM_LPAE
		base = 0x0;
		size = 0x100000000;
#else
		base = 0x0;
		size = 0x100000000;
#endif
	}

	// 分配一个初始的 vmm_area
	va = __alloc_vmm_area_entry(base, size);
	if (!va)
		pr_err("failed to alloc free vmm_area\n");
	// 将 vmm_area 插入到 vmm_area_free 链表
	else
		list_add_tail(&mm->vmm_area_free, &va->list);
}

// 检查 addr 是否在某个 vmm_area 的区域管辖内
static inline int check_vm_address(struct vm *vm, unsigned long addr)
{
	struct vmm_area *va;

	list_for_each_entry(va, &vm->mm.vmm_area_used, list) {
		if ((addr >= va->start) && (addr < va->end))
			return 0;
	}

	return 1;
}

// 
static int vm_memory_init(struct vm *vm)
{
	struct memory_region *region;
	struct vmm_area *va;
	int ret = 0;

	// mvm 创建的 vm 直接返回 0
	if (!vm_is_native(vm))
		return 0;

	/*
	 * find the memory region which belongs to this
	 * VM and register to this VM.
	 */
	// 遍历 mem_region
	for_each_memory_region(region) {
		// 寻找为当前 vm 分配的 mem_region，如果不是 continue
		if (region->vmid != vm->vmid)
			continue;

		// 切割出一个 vmm_area，其 base、size 为 mem_region 大小
		va = split_vmm_area(&vm->mm, region->phy_base,
				region->size, VM_NATIVE_NORMAL);
		if (!va)
			return -EINVAL;
	}

	/*
	 * check whether the entry address, setup_data address and load
	 * address are in the valid memory region.
	 */

	ret = check_vm_address(vm, (unsigned long)vm->load_address);
	ret += check_vm_address(vm, (unsigned long)vm->entry_point);
	ret += check_vm_address(vm, (unsigned long)vm->setup_data);

	return ret;
}

int vm_mm_struct_init(struct vm *vm)
{
	struct mm_struct *mm = &vm->mm;

	mm->pgdp = NULL;
	spin_lock_init(&mm->lock);
	//
	init_list(&mm->vmm_area_free);
	init_list(&mm->vmm_area_used);

	// 分配该 vm 的 stage2 页表/pgd
	mm->pgdp = arch_alloc_guest_pgd();
	if (mm->pgdp == NULL) { 
		pr_err("No memory for vm page table\n");
		return -ENOMEM;
	}
	// 分配和初始化该 vm 的 第一个 vmm_area 结构体
	vmm_area_init(mm, !vm_is_32bit(vm));

	/*
	 * attch the memory region to the native vm.
	 */
	return vm_memory_init(vm);
}

// 对 vmm_area_used 建立 stage2 映射
int vm_mm_init(struct vm *vm)
{
	int ret;
	unsigned long base, end, size;
	struct vmm_area *va, *n;
	struct mm_struct *mm = &vm->mm;

	if (test_and_set_bit(VM_FLAGS_BIT_SKIP_MM_INIT, &vm->flags))
		return 0;

	// dump 出目前所有的 vmm_area 
	dump_vmm_areas(&vm->mm);

	/* just mapping the physical memory for native VM */
	// used vmm_area 都有分配实际的物理内存，这里建立映射关系
	list_for_each_entry(va, &mm->vmm_area_used, list) {
		if (!(va->flags & __VM_NORMAL))
			continue;
		// 建立映射，而且是直接映射, 即 [va->start, va->end) => [va->start, va->end)
		ret = map_vmm_area(mm, va, va->start);
		if (ret) {
			pr_err("map mem failed for vm-%d [0x%lx 0x%lx]\n",
				vm->vmid, va->start, va->end);
			return ret;
		}
	}

	/*
	 * make sure that all the free vmm_area are PAGE aligned
	 * when caculated the end address need to plus 1.
	 */
	// 规整 free vmm_area
	list_for_each_entry_safe(va, n, &mm->vmm_area_free, list) {
		base = BALIGN(va->start, PAGE_SIZE);
		end = ALIGN(va->end, PAGE_SIZE);
		size = end - base;

		if (size < PAGE_SIZE) {
			pr_debug("drop unused vmm_area [0x%lx 0x%lx]\n",
					va->start, va->end);
			list_del(&va->list);
			free(va);
			continue;
		}

		if (size != (va->end - va->start)) {
			pr_debug("adjust vma [0x%lx 0x%lx] to [0x%lx->0x%lx]\n",
					va->start, va->end, base, end);
			va->start = base;
			va->end = end;
		}
	}

	return 0;
}

int vmm_has_enough_memory(size_t size)
{
	return ((size >> MEM_BLOCK_SHIFT) <= free_blocks);
}


// 释放 block_section 中的 bfn 所在的 block
static int __vmm_free_memblock(uint32_t bfn)
{
	// format block 地址
	unsigned long base = bfn << MEM_BLOCK_SHIFT;
	
	struct block_section *bs = bs_head;

	// 遍历所有 block_section
	while (bs) {
		// 该 bfn 所在的 block_section
		if ((base >= bs->start) && (base < bs->end)) {
			// 获取该 bfn 所在 block 在对应的 block_seciton 的比特位
			bfn = (base - bs->start) >> MEM_BLOCK_SHIFT;
			// 清除该比特位
			clear_bit(bfn, bs->bitmap);
			// 更新信息
			bs->free_blocks += 1;
			free_blocks += 1;
			return 0;
		}

		bs = bs->next;
	}

	pr_err("wrong memory block 0x%x\n", bfn);

	return -EINVAL;
}

// 释放掉 block mb
int vmm_free_memblock(struct mem_block *mb)
{
	uint32_t bfn = mb->bfn;
	int ret;

	free(mb);
	spin_lock(&bs_lock);
	ret = __vmm_free_memblock(bfn);
	spin_unlock(&bs_lock);

	return ret;
}

// 从 block_section 中分配一个 mem_block
static int get_memblock_from_section(struct block_section *bs, uint32_t *bfn)
{
	uint32_t id;

	id = find_next_zero_bit_loop(bs->bitmap,
			bs->total_blocks, bs->current_index);
	if (id >= bs->total_blocks)
		return -ENOSPC;

	set_bit(id, bs->bitmap);
	bs->current_index = id + 1;
	bs->free_blocks -= 1;
	free_blocks -= 1;
	*bfn = (bs->start >> MEM_BLOCK_SHIFT) + id;

	return 0;
}

struct mem_block *vmm_alloc_memblock(void)
{
	struct block_ section *bs;
	struct mem_block *mb;
	int success = 0, ret;
	uint32_t bfn = 0;

	spin_lock(&bs_lock);
	bs = bs_head;
	while (bs) {
		if (bs->free_blocks != 0) {
			ret = get_memblock_from_section(bs, &bfn);
			if (ret == 0) {
				success = 1;
				break;
			} else { 
				pr_err("memory block content wrong\n");
			}
		}
		bs = bs->next;
	}
	spin_unlock(&bs_lock);

	if (!success)
		return NULL;

	// 分配 mem_block 结构体
	mb = malloc(sizeof(struct mem_block));
	if (!mb) {
		spin_lock(&bs_lock);
		__vmm_free_memblock(bfn);
		spin_unlock(&bs_lock);
		return NULL;
	}

	mb->bfn = bfn;
	mb->next = NULL;

	return mb;
}

// 遍历 mem_region，将空闲的 NORMAL 内存 转换为 block，作为 guest vm、
// [       0.000000@00 000] NIC MEM: 0x000000004645a000 -> 0x0000000046600000 [0x00000000001a6000] Normal/Host
// 这部分内存小于 1 个 block size，舍弃掉
// [       0.000000@00 000] NIC MEM: 0x0000000086600000 -> 0x00000000c0000000 [0x0000000039a00000] Normal/Host
// 这部分内存转换为 block
void vmm_init(void)
{
	struct memory_region *region;
	struct block_section *bs;
	unsigned long start, end;
	int size;

	ASSERT(!is_list_empty(&mem_list));

	/*
	 * all the free memory will used as the guest VM
	 * memory. The guest memory will allocated as block.
	 */
	// 对于每一个 memory_region
	list_for_each_entry(region, &mem_list, list) {
		// 遍历所有的空闲内存，准备全部用作 guest vm，转换成 block 形式
		if (region->type != MEMORY_REGION_TYPE_NORMAL)
			continue;

		/*
		 * block section need BLOCK align.
		 */
		// 如果该段 mem_region 小于一个 block，放过它
		start = BALIGN(region->phy_base, BLOCK_SIZE);
		end = ALIGN(region->phy_base + region->size, BLOCK_SIZE);
		if (end - start <= 0) {
			pr_warn("VMM drop memory region [0x%lx 0x%lx]\n",
					region->phy_base,
					region->phy_base + region->size);
			continue;
		}

		pr_notice("VMM add memory region [0x%lx 0x%lx]\n", start, end);

		// 分配一个 block_section，记录信息
		bs = malloc(sizeof(struct block_section));
		ASSERT(bs != NULL);
		bs->start = start;
		bs->end = end;
		bs->size = bs->end - bs->start;
		bs->total_blocks = bs->free_blocks = bs->size >> BLOCK_SHIFT;
		bs->current_index = 0;
		free_blocks += bs->total_blocks;

		/*
		 * allocate the memory for block bitmap.
		 */
		// 分配对应的 bitmap
		size = BITS_TO_LONGS(bs->free_blocks) * sizeof(long);
		bs->bitmap = malloc(size);
		ASSERT(bs->bitmap != NULL);
		memset(bs->bitmap, 0, size);

		bs->next = bs_head;
		bs_head = bs;
	}
}
