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
#include <minos/sched.h>
#include <virt/vdev.h>
#include <virt/virq.h>
#include <virt/vmcs.h>
#include <virt/vmm.h>
#include <virt/vm.h>

static void vdev_set_name(struct vdev *vdev, const char *name)
{
	int len;

	if (!vdev || !name)
		return;

	len = strlen(name);
	if (len > VDEV_NAME_SIZE)
		len = VDEV_NAME_SIZE;

	strncpy(vdev->name, name, len);
}

void vdev_release(struct vdev *vdev)
{
	struct vmm_area *vma = vdev->gvm_area;
	struct vmm_area *next;

	if (vdev->list.next != NULL)
		list_del(&vdev->list);

	/*
	 * release the vmm_areas if has. just delete it, the VMM
	 * will release all the vmm_area of VM.
	 */
	while (vma) {
		next = vma->next;
		vma->next = NULL;
		vma = next;
	}
}

static void vdev_deinit(struct vdev *vdev)
{
	pr_warn("using default vdev deinit routine\n");
	vdev_release(vdev);
	free(vdev);
}

void host_vdev_init(struct vm *vm, struct vdev *vdev, const char *name)
{
	if (!vm || !vdev) {
		pr_err("%s: no such VM or VDEV\n");
		return;
	}

	memset(vdev, 0, sizeof(struct vdev));
	vdev->vm = vm;
	vdev->host = 1;
	vdev->list.next = NULL;
	vdev->deinit = vdev_deinit;
	vdev->list.next = NULL;
	vdev->list.pre = NULL;
	vdev_set_name(vdev, name);
}

static void inline vdev_add_vmm_area(struct vdev *vdev, struct vmm_area *va)
{
	struct vmm_area *head = vdev->gvm_area;
	struct vmm_area *prev = NULL;

	/*
	 * add to the list tail.
	 */
	while (head) {
		prev = head;
		head = head->next;
	}

	va->next = NULL;
	if (prev == NULL)
		vdev->gvm_area = va;
	else
		prev->next = va;
}
// 虚拟设备添加内存 范围，只是在该 vm 中分配一个 vma，将信息记录到 vma，没有做映射
// MARK，这里没有做实际的物理内存分配和 stage2映射
// 当 guest read 该段内存的时候，vm trap 到 hyp，然后 hyp 负责给 vm 读取内存数据
int vdev_add_iomem_range(struct vdev *vdev, unsigned long base, size_t size)
{
	struct vmm_area *va;

	if (!vdev || !vdev->vm)
		return -ENOENT;

	/*
	 * vdev memory usually will not mapped to the real
	 * physical space, here set the flags to 0.
	 */
	// 这里相当于将 vdev 的内存范围记录到 vm->mm，但是并没有建立实际的映射
	va = split_vmm_area(&vdev->vm->mm, base, size, VM_GUEST_VDEV);
	if (!va) {
		pr_err("vdev: request vmm area failed 0x%lx 0x%lx\n",
				base, base + size);
		return -ENOMEM;
	}
	// 一个 vm 所有 vdev 内存 vma 连接成一个链表，这里添加
	vdev_add_vmm_area(vdev, va);

	return 0;
}

void vdev_add(struct vdev *vdev)
{
	if (!vdev->vm)
		pr_err("%s vdev has not been init\n");
	else
		list_add_tail(&vdev->vm->vdev_list, &vdev->list);
}

struct vmm_area *vdev_alloc_iomem_range(struct vdev *vdev, size_t size, int flags)
{
	struct vmm_area *va;

	va = alloc_free_vmm_area(&vdev->vm->mm, size, PAGE_MASK, flags);
	if (!va)
		return NULL;

	vdev_add_vmm_area(vdev, va);

	return va;
}

struct vmm_area *vdev_get_vmm_area(struct vdev *vdev, int idx)
{
	struct vmm_area *va = vdev->gvm_area;

	while (idx || !va) {
		va = va->next;
		idx--;
	}

	return va;
}

struct vdev *create_host_vdev(struct vm *vm, const char *name)
{
	struct vdev *vdev;

	vdev = malloc(sizeof(*vdev));
	if (!vdev)
		return NULL;

	host_vdev_init(vm, vdev, name);

	return vdev;
}

static inline int handle_mmio_write(struct vdev *vdev, gp_regs *regs,
		int idx, unsigned long offset, unsigned long *value)
{
	if (vdev->write)
		return vdev->write(vdev, regs, idx, offset, value);
	else
		return 0;
}

static inline int handle_mmio_read(struct vdev *vdev, gp_regs *regs,
		int idx, unsigned long offset, unsigned long *value)
{
	if (vdev->read)
		return vdev->read(vdev, regs, idx, offset, value);
	else
		return 0;
}
// 调用 vdev 的读写函数
static inline int handle_mmio(struct vdev *vdev, gp_regs *regs, int write,
		int idx, unsigned long offset, unsigned long *value)
{
	if (write)
		return handle_mmio_write(vdev, regs, idx, offset, value);
	else
		return handle_mmio_read(vdev, regs, idx, offset, value);
}

// hyp 处理 mmio
int vdev_mmio_emulation(gp_regs *regs, int write,
		unsigned long address, unsigned long *value)
{
	struct vm *vm = get_current_vm();
	struct vdev *vdev;
	struct vmm_area *va;
	int idx, ret = 0;
	// 遍历该 vm 的虚拟设备
	list_for_each_entry(vdev, &vm->vdev_list, list) {
		idx = 0;
		va = vdev->gvm_area;
		// 遍历该虚拟设备的内存空间(vmm_area)
		while (va) {
			// 根据出错地址 ipa 查找该地址落在哪个区间内
			if ((address >= va->start) && (address <= va->end)) {
				// 找到对应的虚拟设备，调用其操作函数来处理 mmio
				ret = handle_mmio(vdev, regs, write,
						idx, address - va->start, value);
				if (ret)
					pr_warn("vm%d %s mmio 0x%lx in %s failed\n", vm->vmid,
							write ? "write" : "read", address, vdev->name);
				return 0;
			}
			idx++;
			va = va->next;
		}
	}

	/*
	 * trap the mmio rw event to hvm if there is no vdev
	 * in host can handle it
	 */
	if (vm_is_native(vm))
		return -EACCES;

	// 给 vm 发通知，告知 vm "我"已经完成 mmio
	ret = trap_vcpu(VMTRAP_TYPE_MMIO, write, address, value);
	if (ret) {
		pr_warn("gvm%d %s mmio 0x%lx failed %d\n", vm->vmid,
				write ? "write" : "read", address, ret);
		ret = (ret == -EACCES) ? -EACCES : 0;
	}

	return ret;
}
