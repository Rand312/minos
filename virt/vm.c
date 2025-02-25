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
#include <minos/irq.h>
#include <config/config.h>
#include <minos/mm.h>
#include <minos/bitmap.h>
#include <virt/os.h>
#include <virt/vm.h>
#include <virt/vmodule.h>
#include <virt/virq.h>
#include <virt/vmm.h>
#include <virt/vdev.h>
#include <virt/vmcs.h>
#include <minos/task.h>
#include <minos/pm.h>
#include <minos/of.h>
#include <virt/resource.h>
#include <generic/gvm.h>
#include <virt/vmbox.h>
#include <minos/shell_command.h>
#include <virt/virt.h>
#include <minos/ramdisk.h>
#include <virt/iommu.h>
#include <asm/cache.h>

static struct vm *host_vm;

// 定义 64 个虚拟机指针实例指针
struct vm *vms[CONFIG_MAX_VM];
int total_vms = 0;
LIST_HEAD(vm_list);

static DEFINE_SPIN_LOCK(vms_lock);
// 定义 vmid bitmap
static DECLARE_BITMAP(vmid_bitmap, CONFIG_MAX_VM);

static int aff_current;
static int native_vcpus;
// 定义 vcpu 亲和性位图，位图大小为 pcpu 数量
// 指示某个 pcpu 上是否有 vcpu
DECLARE_BITMAP(vcpu_aff_bitmap, NR_CPUS);
// 定义相关锁
DEFINE_SPIN_LOCK(affinity_lock);

#define VM_NR_CPUS_CLUSTER 256

// 检查 vcpu 是否离线，即当前 vcpu 的标志是否为 VCPU_STATE_SUSPEND
static inline int vcpu_is_offline(struct vcpu *vcpu)
{
	return check_vcpu_state(vcpu, VCPU_STATE_SUSPEND);
}

// 使得 vcpu 上线，也就是将该 vcpu 对应的 task 添加到 pcpu 的 ready list 上面去
static void vcpu_online(struct vcpu *vcpu)
{
	// 确保此 vcpu 是离线的
	ASSERT(vcpu_is_offline(vcpu));
	// 将该 vcpu 对应的 task 添加到某个 pcpu ready_list 上面去，不需要抢占
	task_ready(vcpu->task, 0);
}

// affinity 转换为 vcpu_id
static int inline affinity_to_vcpuid(struct vm *vm, unsigned long affinity)
{
	int aff0, aff1;

	/*
	 * how to handle big-little soc ? usually the hvm's
	 * cpu map is as same as the true hardware, so here
	 * if the VM is the VM0, the affinity is as same as
	 * the real hardware.  hvm = vm0
	 *
	 * Can be different with real hardware ? TBD.
	 */
	if (vm_is_host_vm(vm))
		return affinity_to_cpuid(affinity);

	aff1 = (affinity >> 8) & 0xff;
	aff0 = affinity & 0xff;

	return (aff1 * VM_NR_CPUS_CLUSTER) + aff0;
}

// power on vcpu
int vcpu_power_on(struct vcpu *caller, unsigned long affinity,
		  unsigned long entry, unsigned long unsed)
{
	int cpuid;
	struct vcpu *vcpu;

	// 获取 vcpu_id
	cpuid = affinity_to_vcpuid(caller->vm, affinity);
	// 获取 vm 中第 cpuid 个 vcpu
	vcpu = get_vcpu_in_vm(caller->vm, cpuid);
	if (!vcpu) {
		pr_err("no such:%d->0x%x vcpu for this VM %s\n", cpuid,
		       affinity, caller->vm->name);
		return -ENOENT;
	}

	// 正确状态：如果当前 vcpu 处于离线状态
	if (vcpu_is_offline(vcpu)) {
		pr_notice("vcpu-%d of vm-%d power on 0x%p\n", vcpu->vcpu_id,
			  vcpu->vm->vmid, entry);
		// 调用 os->ops->vcpu_power_on 方法，NOTE 不是 platform 的方法
		os_vcpu_power_on(vcpu, ULONG(entry));
		// vcpu task 挂入 pcpu
		vcpu_online(vcpu);
		// 错误状态：当前 vcpu 处于非离线状态
	} else {
		pr_err("vcpu_power_on : invalid vcpu state %d\n");
		return -EINVAL;
	}

	return 0;
}

// arch_vcpu_state_save
void vcpu_context_save(struct task *task)
{
	save_vcpu_vmodule_state(task_to_vcpu(task));
}

// arch_vcpu_state_restore
void vcpu_context_restore(struct task *task)
{
	restore_vcpu_vmodule_state(task_to_vcpu(task));
}

// 当前 vcpu 是否可以 idle
// 不能 idle 的情况：处于非离线状态、task 需要 freeze | stop、vcpu 中有 irq 正处于 pending | active
static int vcpu_can_idle(struct vcpu *vcpu)
{
	if (vcpu->vm->state != VM_STATE_ONLINE)
		return 0;

	if (is_task_need_stop(vcpu->task))
		return 0;

	if (vcpu_has_irq(vcpu))
		return 0;

	return 1;
}

// vcpu idle，即等待 vcpu_event 事件
int vcpu_idle(struct vcpu *vcpu)
{
	return wait_event(&vcpu->vcpu_event, vcpu_can_idle(vcpu), 0);
}

// vcpu suspend，也就是 idle
int vcpu_suspend(struct vcpu *vcpu, gp_regs *c, uint32_t state,
		 unsigned long entry)
{
	/*
	 * just call vcpu idle to put vcpu to suspend state
	 * and ignore the wake up entry, since the vcpu will
	 * not really powered off
	 */
	return vcpu_idle(vcpu);
}

// vcpu off，设置 task 标志位：TIF_NEED_FREEZE
int vcpu_off(struct vcpu *vcpu)
{
	task_need_freeze(vcpu->task);
	return 0;
}

//
static int vm_check_vcpu_affinity(int vmid, uint32_t *aff, int nr)
{
	int i;
	uint64_t mask = 0;

	//
	for (i = 0; i < nr; i++) {
		if (aff[i] >= VM_MAX_VCPU)
			return -EINVAL;

		if (mask & (1 << aff[i]))
			return -EINVAL;
		else
			mask |= (1 << aff[i]);
	}

	return 0;
}

// 根据 vcpu_id 获取 vm 中的 vcpu 指针
struct vcpu *get_vcpu_in_vm(struct vm *vm, uint32_t vcpu_id)
{
	if (vcpu_id >= vm->vcpu_nr)
		return NULL;

	return vm->vcpus[vcpu_id];
}

// 根据 vmid 和 vcpu_id 获取 vcpu 指针
struct vcpu *get_vcpu_by_id(uint32_t vmid, uint32_t vcpu_id)
{
	struct vm *vm;

	vm = get_vm_by_id(vmid);
	if (!vm)
		return NULL;

	return get_vcpu_in_vm(vm, vcpu_id);
}

//
int kick_vcpu(struct vcpu *vcpu, int reason)
{
	int mode, ret = 0;

	/*
	 * 1 - whether need to wake up the task.
	 * 2 - whether need to send a resched irq.
	 *
	 * if the vcpu is in stop state, only the BootCPU
	 * can wake up it. this will be another path.
	 */
	// 唤醒 vcpu
	ret = wake(&vcpu->vcpu_event);

	/*
	 * 0   - wakeup successfuly
	 * 1   - do not need wake up task
	 * < 0 - wake up failed
	 * if on the same cpu, just call cond_resched to
	 * see whether need preempt this task.
	 */
	if (smp_processor_id() == vcpu_affinity(vcpu))
		return ret;

	/*
	 * ret < 0 means the task do not need to wake up and in ready state.
	 * if task is in ready state, or the task is running in guest mode
	 * then need send a physical irq to the target irq.
	 *
	 * if the virq is not hardware virq, when the native
	 * wfi is enabled for the target vcpu, the target vcpu
	 * may not receive the virq immediately, and may wait
	 * last physical irq come, then this pcpu can wakeup
	 * from the WFI mode, so here need to send a phyical
	 * irq to the target pcpu. Native WFI VCPU will always
	 * in running mode in EL1.
	 */
	mode = vcpu->mode;
	smp_rmb();

	if ((ret < 0) && (mode != IN_ROOT_MODE))
		pcpu_resched(vcpu_affinity(vcpu));
	else if ((ret < 0) && (vcpu->vm->flags & VM_FLAGS_NATIVE_WFI))
		pcpu_resched(vcpu_affinity(vcpu));

	return ret;
}

// 释放 vcpu
static void inline release_vcpu(struct vcpu *vcpu)
{
	/*
	 * need to make sure that when free the memory resource
	 * can not be done in the interrupt context, so the
	 * destroy a task will done in the idle task, here
	 * just call vmodule_stop call back, then set the
	 * task to the stop list of the pcpu, when the idle
	 * task is run, the idle task will release this task
	 */
	if (vcpu->context)
		stop_vcpu_vmodule_state(vcpu);

	if (vcpu->task)
		do_release_task(vcpu->task);

	if (vcpu->vmcs_irq >= 0)
		release_hvm_virq(vcpu->vmcs_irq);

	if (vcpu->virq_struct)
		free(vcpu->virq_struct);

	free(vcpu);
}

// 分配 vcpu
static struct vcpu *alloc_vcpu(void)
{
	struct vcpu *vcpu;

	// zalloc 分配 vcpu 结构体
	vcpu = zalloc(sizeof(*vcpu));
	if (!vcpu)
		return NULL;

	// 分配 virq_struct 结构体
	vcpu->virq_struct = zalloc(sizeof(struct virq_struct));
	if (!vcpu->virq_struct)
		goto free_vcpu;

	// 初始化 vmcs_irq 为 -1，这是？？？？？？？？
	vcpu->vmcs_irq = -1;
	return vcpu;

free_vcpu:
	free(vcpu);

	return NULL;
}

// 返回虚机时需要额外执行的一些列操作
static void vcpu_return_to_user(struct task *task, gp_regs *regs)
{
	struct vcpu *vcpu = (struct vcpu *)task->pdata;

	vcpu->mode =
		OUTSIDE_ROOT_MODE; // 此时仍然在处于 EL2 hypervisor 中，设置为 ROOT mode
	smp_wmb();

	// 执行 OS_HOOK_ENTER_TO_GUEST 类型的 hook 函数
	do_hooks(vcpu, (void *)regs, OS_HOOK_ENTER_TO_GUEST);

	smp_wmb();
	vcpu->mode = IN_GUEST_MODE; // 将要进入虚机，设置为 GUEST mode
}

static void vcpu_exit_from_user(struct task *task, gp_regs *regs)
{
	struct vcpu *vcpu = (struct vcpu *)task->pdata;

	vcpu->mode = OUTSIDE_GUEST_MODE;
	smp_wmb();

	do_hooks(vcpu, (void *)regs, OS_HOOK_EXIT_FROM_GUEST);

	smp_wmb();
	vcpu->mode = IN_ROOT_MODE;
}

// 创建 vcpu
static struct vcpu *create_vcpu(struct vm *vm, uint32_t vcpu_id)
{
	char name[64];
	struct vcpu *vcpu;
	struct task *task;

	/* generate the name of the vcpu task */
	memset(name, 0, 64);
	sprintf(name, "%s-vcpu-%d", vm->name, vcpu_id);
	// 创建 vcpu 线程
	task = create_vcpu_task(name, vm->entry_point,
				vm->vcpu_affinity[vcpu_id], 0, NULL);
	if (task == NULL)
		return NULL;

	// 设置进入退出 guest 的方法
	task->return_to_user = vcpu_return_to_user;
	task->exit_from_user = vcpu_exit_from_user;

	// 分配一个 vcpu
	vcpu = alloc_vcpu();
	if (!vcpu) {
		do_release_task(task);
		return NULL;
	}

	// 初始化 vcpu 字段
	task->pdata = vcpu; // struct task 的私有数据设置为 vcpu 结构
	vcpu->task = task;
	vcpu->vcpu_id = vcpu_id;
	vcpu->vm = vm;
	vcpu->mode = IN_ROOT_MODE; // 表示正位于 EL2

	if (vm->flags & VM_FLAGS_32BIT)
		task->flags |= TASK_FLAGS_32BIT;

	// 初始该 vcpu 的 virq_struct，即初始 percpu 中断相关信息
	vcpu_virq_struct_init(vcpu);
	vm->vcpus[vcpu_id] = vcpu;
	event_init(&vcpu->vcpu_event, OS_EVENT_TYPE_NORMAL, task);

	// 更新 vcpus 数组
	vcpu->next = NULL;
	if (vcpu_id != 0)
		vm->vcpus[vcpu_id - 1]->next = vcpu;

	return vcpu;
}

static int alloc_new_vmid(void)
{
	int vmid, start = total_vms;

	spin_lock(&vms_lock);
	vmid = find_next_zero_bit_loop(vmid_bitmap, CONFIG_MAX_VM, start);
	if (vmid >= CONFIG_MAX_VM) {
		vmid = 0;
		goto out;
	}

	set_bit(vmid, vmid_bitmap);
out:
	spin_unlock(&vms_lock);

	return vmid;
}

static int vcpu_affinity_init(void)
{
	int i;
	struct vm *vm;

	// 清空位图设置
	bitmap_clear(vcpu_aff_bitmap, 0, NR_CPUS);

	// 遍历所有的 vm
	for_each_vm(vm)
	{
		// 如果某个 vm 的 vcpu 亲和 pcpu，那么将 pcpu 对应的位置 1
		for (i = 0; i < vm->vcpu_nr; i++)
			set_bit(vm->vcpu_affinity[i], vcpu_aff_bitmap);
	}

	aff_current = find_first_zero_bit(vcpu_aff_bitmap, NR_CPUS);
	if (aff_current >= NR_CPUS)
		aff_current = (NR_CPUS - 1);

	for (i = 0; i < NR_CPUS; i++) {
		if (test_bit(i, vcpu_aff_bitmap))
			native_vcpus++;
	}

	return 0;
}

void get_vcpu_affinity(uint32_t *aff, int nr)
{
	int i = 0;
	int vm0_vcpu0_ok = 0;
	int vm0_vcpus_ok = 0;
	struct vm *vm0 = get_host_vm();
	int vm0_vcpu0 = vm0->vcpu_affinity[0];

	if (nr == NR_CPUS)
		vm0_vcpu0_ok = 1;
	else if (nr > (NR_CPUS - native_vcpus))
		vm0_vcpus_ok = 1;

	spin_lock(&affinity_lock);

	do {
		if (!test_bit(aff_current, vcpu_aff_bitmap)) {
			aff[i] = aff_current;
			i++;
		} else {
			if ((aff_current == vm0_vcpu0) && vm0_vcpu0_ok) {
				aff[i] = aff_current;
				i++;
			} else if ((aff_current != vm0_vcpu0) && vm0_vcpus_ok) {
				aff[i] = aff_current;
				i++;
			}
		}

		if (++aff_current >= NR_CPUS)
			aff_current = 0;
	} while (i < nr);

	spin_unlock(&affinity_lock);
}

static int vmtag_check_and_config(struct vmtag *tag)
{
	size_t size;

	/*
	 * first check whether there are enough memory for
	 * this vm and the vm's memory base need to be start
	 * at 0x80000000 or higher, if the mem_base is 0,
	 * then set it to default 0x80000000
	 */
	size = tag->mem_size;
	if (tag->mem_base == 0)
		tag->mem_base = GVM_NORMAL_MEM_START;

	if (!vmm_has_enough_memory(size)) {
		pr_err("no enough memory for guest\n");
		return -ENOMEM;
	}

	if (tag->nr_vcpu > NR_CPUS) {
		pr_err("to much vcpus for guest\n");
		return -EINVAL;
	}

	/* for the dynamic need to get the affinity dynamicly */
	if (tag->flags & VM_FLAGS_DYNAMIC_AFF) {
		memset(tag->vcpu_affinity, 0, sizeof(tag->vcpu_affinity));
		get_vcpu_affinity(tag->vcpu_affinity, tag->nr_vcpu);
	}

	return 0;
}

int request_vm_virqs(struct vm *vm, int base, int nr)
{
	if (!vm || (base < GVM_IRQ_BASE) || (nr <= 0) ||
	    (base + nr >= GVM_IRQ_END))
		return -EINVAL;

	while (nr > 0) {
		if (request_virq(vm, base, 0)) {
			pr_err("request virq %d in GVM %s failed\n", base,
			       vm->name);
			return -ENOENT;
		}
		base++;
		nr--;
	}

	return 0;
}

// 加载 vm 对应的 image 文件
static int load_vm_image(struct vm *vm)
{
	void *addr = (void *)ptov(vm->load_address);
	size_t size;
	int ret;

	if (!vm->kernel_file)
		return 0;

	// 加载镜像文件（kernel 镜像）到 load_address(entry)
	pr_notice("copying %s to 0x%x\n", ramdisk_file_name(vm->kernel_file),
		  vm->load_address);

	// 获取镜像文件大小
	size = ramdisk_file_size(vm->kernel_file);
	ret = create_host_mapping(ULONG(addr), ULONG(vm->load_address),
				  PAGE_BALIGN(size), VM_NORMAL | VM_HUGE);
	ASSERT(ret == 0);

	ret = ramdisk_read(vm->kernel_file, addr, size, 0);
	ASSERT(ret == 0);

	flush_dcache_range(ULONG(addr), PAGE_BALIGN(size));
	destroy_host_mapping(ULONG(addr), PAGE_BALIGN(size));

	return 0;
}

// 启动 vm，也就是启动 vcpu0
static int do_start_vm(struct vm *vm)
{
	struct vcpu *vcpu0;
	// get vcpu0
	vcpu0 = vm->vcpus[0];
	if (!vcpu0) {
		pr_err("VM create with error, vm%d not exist\n", vm->vmid);
		return -ENOENT;
	}

	/*
	 * flush all the tlb for this vm.
	 */
	flush_all_tlb_mm(&vm->mm);

	vcpu_online(vcpu0);

	return 0;
}

int start_guest_vm(struct vm *vm)
{
	int state;

	if (!vm) {
		pr_err("no such guest vm\n");
		return -ENOENT;
	}

	// 切换 vm 状态
	state = cmpxchg(&vm->state, VM_STATE_OFFLINE, VM_STATE_ONLINE);
	if (state != VM_STATE_OFFLINE) {
		pr_err("VM %s already stared\n", vm->name);
		return -EINVAL;
	}

	vm_vcpus_init(vm);

	/*
	 * start the vm now
	 */
	return do_start_vm(vm);
}
// 之前初始化创建的 vma 结构体是整个 ipa 空间大小
// 这里切出一个小的，用于创建 vm 时指定的 base,size；并且实际分配内存
static int guest_mm_init(struct vm *vm, uint64_t base, uint64_t size)
{
	if (split_vmm_area(&vm->mm, base, size, VM_GUEST_NORMAL) == NULL) {
		pr_err("invalid memory config for guest VM\n");
		return -EINVAL;
	}

	if (alloc_vm_memory(vm)) {
		pr_err("allocate memory for vm-%d failed\n", vm->vmid);
		return -ENOMEM;
	}

	return 0;
}

int create_vm_mmap(int vmid, unsigned long offset, unsigned long size,
		   unsigned long *addr)
{
	struct vm *vm = get_vm_by_id(vmid);
	struct vmm_area *va;

	va = vm_mmap(vm, offset, size);
	if (va) {
		*addr = va->start;
		return 0;
	}

	return -EINVAL;
}
// 这个 tag 应该是 guest 中的一个 内核地址
int create_guest_vm(struct vmtag __guest *tag)
{
	int ret = 0;
	struct vm *vm;
	struct vmtag vmtag;

	memset(&vmtag, 0, sizeof(struct vmtag));
	// 从 guest kernel 中获取 vmtag 信息，MARK，guest 和 host 对 vmtag 的定义不一样
	ret = copy_from_guest(&vmtag, tag, sizeof(struct vmtag));
	if (ret != 0) {
		pr_err("copy vmtag from guest failed\n");
		return -EFAULT;
	}

	ret = vmtag_check_and_config(&vmtag);
	if (ret)
		return ret;

	vmtag.vmid = 0;
	vmtag.flags |= VM_FLAGS_CAN_RESET;
	vm = create_vm(&vmtag, NULL);
	if (!vm)
		return -ENOMEM;

	ret = guest_mm_init(vm, vmtag.mem_base, vmtag.mem_size);
	if (ret) {
		destroy_vm(vm);
		return ret;
	}

	return vm->vmid;
}

static int create_vm_resource(struct vm *vm)
{
	int ret;

	/*
	 * do not need to create the resource again, when reboot
	 * or shutdown.
	 */
	if (test_and_set_bit(VM_FLAGS_BIT_SKIP_CREATE_RES, &vm->flags))
		return 0;

	if (vm_is_native(vm)) {
		ret = os_create_native_vm_resource(vm);
		if (ret)
			return ret;
		ret = create_vmbox_controller(vm);
	} else {
		ret = os_create_guest_vm_resource(vm);
	}

	return ret;
}

static void __setup_native_vm(struct vm *vm)
{
	void *setup_addr = (void *)ptov(vm->setup_data);
	size_t size;
	int ret;

	/*
	 * first load the setup data from the ramdisk if needed.
	 * the setup data ususally is device tree on ARM, need
	 * map the memory into hypervisor's space. The memory
	 * of setup data can not beyond 2M.
	 */
	// arm 平台的设备树文件中记录了 setup_data 的地址
	// 这里将 setup_data 地址映射到 hyp 的地址空间
	// 然后将设备树文件拷贝到 setup_data 地址处
	if (vm->dtb_file) {
		pr_notice("copying %s to 0x%x\n",
			  ramdisk_file_name(vm->dtb_file), vm->setup_data);
		size = ramdisk_file_size(vm->dtb_file);
		// 创建映射，是的 hyp 能够访问 setup_addr
		ret = create_host_mapping(ULONG(setup_addr),
					  ULONG(vm->setup_data), MAX_DTB_SIZE,
					  VM_NORMAL | VM_HUGE);
		ASSERT(ret == 0);

		ret = ramdisk_read(vm->dtb_file, setup_addr, size, 0);
		ASSERT(ret == 0);
	} else {
		ret = create_host_mapping(ULONG(setup_addr),
					  ULONG(vm->setup_data), MAX_DTB_SIZE,
					  VM_NORMAL | VM_HUGE);
		ASSERT(ret == 0);
	}

	/*
	 * here need to create the resource based on the vm's
	 * os, when the os is a linux system, usually it will
	 * used device tree, if the os is rtos, need to write
	 * the iomem and virqs in the hypervisor's device tree
	 *
	 * here to check whether there are information in the
	 * hypervisor's dts, if not then try to parsing the dtb
	 * of the VM
	 *
	 * first map the dtb address to the hypervisor, here
	 * map these native VM's memory as read only
	 *
	 * just do these step only when the VM has not been
	 * online.
	 */
	// 根据 qemu-arm64.dts 创建 vm 需要的资源，比如 pdev, vdev
	create_vm_resource(vm);

	// 根据 qemu-arm64.dts 创建 memory cpu 等资源
	os_setup_vm(vm);
	do_hooks(vm, NULL, OS_HOOK_SETUP_VM);

	/*
	 * the DTB content may modified, get the final size, and
	 * then flush the cache and unmap the memory.
	 */
	size = fdt_totalsize(setup_addr);
	flush_dcache_range(ULONG(setup_addr), PAGE_BALIGN(size));
	destroy_host_mapping(ULONG(setup_addr), MAX_DTB_SIZE);
}

void destroy_vm(struct vm *vm)
{
	int i;
	unsigned long flags;
	struct vdev *vdev, *n;
	struct vcpu *vcpu;

	if (!vm)
		return;

	if (vm_is_native(vm))
		panic("can not destory native VM\n");

	/*
	 * 1 : release the vdev
	 * 2 : do hooks for each modules
	 * 3 : release the vcpu allocated to this vm
	 * 4 : free the memory for this VM
	 * 5 : update the vmid bitmap
	 * 6 : do vmodule deinit
	 */
	list_for_each_entry_safe (vdev, n, &vm->vdev_list, list) {
		list_del(&vdev->list);
		if (vdev->deinit)
			vdev->deinit(vdev);
	}

	do_hooks((void *)vm, NULL, OS_HOOK_DESTROY_VM);

	if (vm->vcpus) {
		for (i = 0; i < vm->vcpu_nr; i++) {
			vcpu = vm->vcpus[i];
			if (!vcpu)
				continue;
			release_vcpu(vcpu);
		}

		free(vm->vcpus);
	}

	release_vm_memory(vm);

	i = vm->vmid;
	spin_lock_irqsave(&vms_lock, flags);
	clear_bit(i, vmid_bitmap);
	list_del(&vm->vm_list);
	vms[i] = NULL;
	total_vms--;
	spin_unlock_irqrestore(&vms_lock, flags);

	free(vm);
}

int vm_vcpus_init(struct vm *vm)
{
	struct vcpu *vcpu;

	vm_for_each_vcpu(vm, vcpu)
	{
		pr_notice("vm-%d vcpu-%d affnity to pcpu-%d\n", vm->vmid,
			  vcpu->vcpu_id, vcpu_affinity(vcpu));
		/*
		 * init the vcpu context here.
		 */
		// 初始化 vcpu 上下文
		vcpu_vmodules_init(vcpu);

		if (!vm_is_native(vm)) {
			vcpu->vmcs->host_index = 0;
			vcpu->vmcs->guest_index = 0;
		}
	}

	// 对该 vm 中所有的 vcpu 执行相应的 hook
	vm_for_each_vcpu(vm, vcpu)
	{
		do_hooks(vcpu, NULL, OS_HOOK_VCPU_INIT);
		// 准备 vcpu 线程堆栈，当该 vcpu 线程被调度执行时，就会从 pc 指向的 entry 开始执行
		os_vcpu_power_on(vcpu, (unsigned long)vm->entry_point);
	}

	return 0;
}

static int create_vcpus(struct vm *vm)
{
	int i, j;
	struct vcpu *vcpu;

	for (i = 0; i < vm->vcpu_nr; i++) {
		vcpu = create_vcpu(vm, i);
		if (!vcpu) {
			pr_err("create vcpu:%d for %s failed\n", i, vm->name);
			for (j = 0; j < vm->vcpu_nr; j++) {
				vcpu = vm->vcpus[j];
				if (!vcpu)
					continue;
				release_vcpu(vcpu);
			}

			return -ENOMEM;
		}
	}

	return 0;
}

// vm
static void vm_open_ramdisk_file(struct vm *vm, struct vmtag *vme)
{
	// mvm 创建的 vm，不是 native
	if (!vm_is_native(vm))
		return;

	if (vme->kernel_file) {
		vm->kernel_file = malloc(sizeof(struct ramdisk_file));
		ASSERT(vm->kernel_file != NULL);
		ASSERT(ramdisk_open(vme->kernel_file, vm->kernel_file) == 0);
	}

	if (vme->dtb_file) {
		vm->dtb_file = malloc(sizeof(struct ramdisk_file));
		ASSERT(vm->dtb_file != NULL);
		ASSERT(ramdisk_open(vme->dtb_file, vm->dtb_file) == 0);
	}

	if (vme->initrd_file) {
		vm->initrd_file = malloc(sizeof(struct ramdisk_file));
		ASSERT(vm->initrd_file != NULL);
		ASSERT(ramdisk_open(vme->initrd_file, vm->initrd_file) == 0);
	}
}

// 设置 vm 结构体
static struct vm *__create_vm(struct vmtag *vme)
{
	struct vm *vm;

	if (vm_check_vcpu_affinity(vme->vmid, vme->vcpu_affinity,
				   vme->nr_vcpu)) {
		pr_err("vcpu affinity for vm not correct\n");
		return NULL;
	}

	// 创建 vm struct
	vm = malloc(sizeof(*vm));
	if (!vm)
		return NULL;

	vme->nr_vcpu = MIN(vme->nr_vcpu, VM_MAX_VCPU);
	memset(vm, 0, sizeof(struct vm));
	// 创建 vcpu
	vm->vcpus = malloc(sizeof(struct vcpu *) * vme->nr_vcpu);
	if (!vm->vcpus) {
		free(vm);
		return NULL;
	}

	vm->vmid = vme->vmid;
	vm->flags |= vme->flags;
	strncpy(vm->name, vme->name, sizeof(vm->name) - 1);
	vm->vcpu_nr = vme->nr_vcpu;
	vm->entry_point = (void *)vme->entry;
	vm->setup_data = (void *)vme->setup_data;
	vm->load_address =
		(void *)(vme->load_address ? vme->load_address : vme->entry);
	vm->state = VM_STATE_OFFLINE;
	init_list(&vm->vdev_list);
	memcpy(vm->vcpu_affinity, vme->vcpu_affinity,
	       sizeof(uint32_t) * VM_MAX_VCPU);

	/*
	 * open the ramdisk file if the vm need load from
	 * the ramdisk.
	 */

	vm_open_ramdisk_file(vm, vme);

	spin_lock(&vms_lock);
	// 注册该 vm 到 vms
	vms[vme->vmid] = vm;
	list_add_tail(&vm_list, &vm->vm_list);
	total_vms++;
	spin_unlock(&vms_lock);

	vm->os = get_vm_os((char *)vme->os_type);

	return vm;
}

struct vm *create_vm(struct vmtag *vme, struct device_node *node)
{
	int ret = 0;
	struct vm *vm;
	//
	if (vme->vmid != 0) {
		pr_notice("request vmid %d\n", vme->vmid);
		if (test_and_set_bit(vme->vmid, vmid_bitmap))
			return NULL;
		// MARK，调试的时候发现 mvm 走这里，vmid 应该为 -1 ？？？？？？？
	} else {
		vme->vmid = alloc_new_vmid(); // 从 vmid bitmap 中分配一个 vmid
		if (vme->vmid == 0)
			return NULL;
	}
	// 初始化 vm 结构体信息
	vm = __create_vm(vme);
	if (!vm)
		return NULL;

	vm->dev_node = node;

	ret = vm_mm_struct_init(vm);
	if (ret) {
		pr_err("mm struct init failed\n");
		goto release_vm;
	}

	// qemu 平台没有
	iommu_vm_init(vm);

	ret = create_vcpus(vm);
	if (ret) {
		pr_err("create vcpus for vm failded\n");
		ret = 0;
		goto release_vm;
	}

	// vm1 具有 host-vm 属性，为 host_vm
	if ((vm->flags & VM_FLAGS_HOST)) {
		ASSERT(host_vm == NULL);
		host_vm = vm;
	}

	// virq_create_vm，初始化 virq_struct 结构体
	// hostvm 会调用 qemu_setup_hvm
	if (do_hooks((void *)vm, NULL, OS_HOOK_CREATE_VM)) {
		pr_err("create vm failed in hook function\n");
		goto release_vm;
	}

	return vm;

release_vm:
	destroy_vm(vm);

	return NULL;
}

struct vm *get_host_vm(void)
{
	return host_vm;
}

static inline const char *get_vm_type(struct vm *vm)
{
	if (vm->flags & VM_FLAGS_HOST)
		return "Host";
	else if (vm->flags & VM_FLAGS_NATIVE)
		return "Native";
	else
		return "Guest";
}
// hypervisor 自己分析配置文件创建的 vm 就是 native vm
static void *create_native_vm_of(struct device_node *node, void *arg)
{
	struct vmtag vmtag;

	if (node->class != DT_CLASS_VM)
		return NULL;

	if (parse_vm_info_of(node, &vmtag))
		return NULL;

	pr_notice("**** create new vm ****\n");
	pr_notice("    vmid: %d\n", vmtag.vmid);
	pr_notice("    name: %s\n", vmtag.name);
	pr_notice("    os_type: %s\n", vmtag.os_type);
	pr_notice("    nr_vcpu: %d\n", vmtag.nr_vcpu);
	pr_notice("    entry: 0x%p\n", vmtag.entry);
	pr_notice("    setup_data: 0x%p\n", vmtag.setup_data);
	pr_notice("    load-address: 0x%p\n", vmtag.load_address);
	pr_notice("    kernel-file: %s\n",
		  vmtag.kernel_file ? vmtag.kernel_file : "NULL");
	pr_notice("    dtb-file: %s\n",
		  vmtag.dtb_file ? vmtag.dtb_file : "NULL");
	pr_notice("    initrd-file: %s\n",
		  vmtag.initrd_file ? vmtag.initrd_file : "NULL");
	pr_notice("    %s-bit vm\n",
		  vmtag.flags & VM_FLAGS_32BIT ? "32" : "64");
	pr_notice("    flags: 0x%x\n", vmtag.flags);
	pr_notice("    affinity: %d %d %d %d %d %d %d %d\n",
		  vmtag.vcpu_affinity[0], vmtag.vcpu_affinity[1],
		  vmtag.vcpu_affinity[2], vmtag.vcpu_affinity[3],
		  vmtag.vcpu_affinity[4], vmtag.vcpu_affinity[5],
		  vmtag.vcpu_affinity[6], vmtag.vcpu_affinity[7]);

	return create_vm(&vmtag, node);
}

// 解析设备树 vms 节点，创建 vm
static void parse_and_create_vms(void)
{
#ifdef CONFIG_DEVICE_TREE
	struct device_node *node;
	node = of_find_node_by_name(of_root_node, "vms");
	if (node)
		// 对设备树中出现的 vm 节点，调用 create_native_vm_of 来创建新的vm
		of_iterate_all_node_loop(node, create_native_vm_of, NULL);
#endif
}

static int of_create_vmboxs(void)
{
	struct device_node *mailboxes;
	struct device_node *child;

	mailboxes = of_find_node_by_name(of_root_node, "vmboxs");
	if (!mailboxes)
		return -ENOENT;

	/* parse each mailbox entry and create it */
	of_node_for_each_child(mailboxes, child)
	{
		if (of_create_vmbox(child))
			pr_err("create vmbox [%s] fail\n", child->name);
		else
			pr_notice("create vmbox [%s] successful\n",
				  child->name);
	}

	return 0;
}

static void setup_native_vm(struct vm *vm)
{
	os_vm_init(vm);
	__setup_native_vm(vm);
	load_vm_image(vm);
	vm_mm_init(vm);
	vm_vcpus_init(vm);
}

int start_native_vm(struct vm *vm)
{
	int state;

	if (!vm) {
		pr_err("no such vm\n");
		return -ENOENT;
	}

	state = cmpxchg(&vm->state, VM_STATE_OFFLINE, VM_STATE_ONLINE);
	if (state != VM_STATE_OFFLINE) {
		pr_err("VM %s already stared\n", vm->name);
		return -EINVAL;
	}

	if (!vm_is_native(vm)) {
		pr_err("can not start guest vm by host\n");
		return -EPERM;
	}

	setup_native_vm(vm);

	return do_start_vm(vm);
}

int virt_init(void)
{
	extern void vmm_init(void);
	extern void vm_daemon_init(void);
	struct vm *vm;

	/*
	 * VMID 0 is reserved
	 */
	// 初始化 vmid 位图
	set_bit(0, vmid_bitmap);
	vmm_init();

	vm_daemon_init();

	parse_and_create_vms();

	/* check whether host VM has been create correctly */
	vm = get_host_vm();
	if (!vm) {
		pr_err("hvm has not been create correctly\n");
		return -ENOENT;
	}

	vcpu_affinity_init();

#ifdef CONFIG_DEVICE_TREE
	/* here create all the mailbox for all native vm */
	// qemu 平台目前没有
	of_create_vmboxs();
#endif

	return 0;
}

void start_all_vm(void)
{
	struct vm *vm;

	list_for_each_entry (vm, &vm_list, vm_list)
		start_native_vm(vm);
}

/*
 * vm start 0 - start the vm which vmid is 0
 */
static int vm_command_hdl(int argc, char **argv)
{
	uint32_t vmid;

	if (argc > 2 && strcmp(argv[1], "start") == 0) {
		vmid = atoi(argv[2]);
		if (vmid == 0)
			start_all_vm();
		else
			start_native_vm(get_vm_by_id(vmid));
	}

	return 0;
}
DEFINE_SHELL_COMMAND(vm, "vm", "virtual machine cmd", vm_command_hdl, 2);
