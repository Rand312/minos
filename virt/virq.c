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
#include <minos/irq.h>
#include <minos/sched.h>
#include <virt/virq.h>
#include <virt/virq_chip.h>

static DEFINE_SPIN_LOCK(hvm_irq_lock);

#define HVM_IRQ_LOCK(vm) 				\
	do {						\
		if (vm_is_host_vm(vm))			\
			spin_lock(&hvm_irq_lock); 	\
	} while (0)

#define HVM_IRQ_UNLOCK(vm) 				\
	do {						\
		if (vm_is_host_vm(vm))			\
			spin_unlock(&hvm_irq_lock); 	\
	} while (0)


// 根据 virq 获取对应的 virq_desc 结构体
// local virq(sgi ppi) 为每个 cpu 拥有的，所以将 local_desc 定义于 vcpu 中
// spi 为所有该 vm 中的 vcpu 中共享，所以将 vspi_desc 定义与 vm 中
struct virq_desc *get_virq_desc(struct vcpu *vcpu, uint32_t virq)
{
	struct vm *vm = vcpu->vm;

	// if virq < 32
	if (virq < VM_LOCAL_VIRQ_NR)
		// 直接返回对应的 virq_desc
		return &vcpu->virq_struct->local_desc[virq];

	// 如果 virq 大于了最大号数
	if (virq >= VM_VIRQ_NR(vm->vspi_nr))
		return NULL;
	
	// virq-32 即为对应的下标值
	return &vm->vspi_desc[VIRQ_SPI_OFFSET(virq)];
}

// 完成 send virq 或者完成其他啥之后，踢 cpu 一脚，提醒 vcpu 该进行某些操作？？？
static void inline virq_kick_vcpu(struct vcpu *vcpu,
		struct virq_desc *desc)
{
	kick_vcpu(vcpu, virq_is_hw(desc) ?
			VCPU_KICK_REASON_HIRQ: VCPU_KICK_REASON_VIRQ);
}

// send virq，主要就是设置 vcpu 中对应的 virq_struct pending 位图
static int inline __send_virq(struct vcpu *vcpu, struct virq_desc *desc)
{
	struct virq_struct *virq_struct = vcpu->virq_struct;

	/*
	 * if the virq is already at the pending state, do
	 * nothing, other case need to send it to the vcpu
	 * if the virq is in offline state, send it to vcpu
	 * directly.
	 *
	 * SGI need set the irq source.
	 */
	//将 virq 设置到 pending_bitmap
	if (test_and_set_bit(desc->vno, virq_struct->pending_bitmap))
		return 0;
	
	// pending_virq ++
	atomic_inc(&virq_struct->pending_virq);
	// 如果是 sgi 类型的 virq，设置来源 cpu 为当前 cpu
	if (desc->vno < VM_SGI_VIRQ_NR)
		desc->src = get_vcenter_pu_id(get_current_vcpu());

	return 0;
}

// 发送 virq 给某个 vcpu
static int send_virq(struct vcpu *vcpu, struct virq_desc *desc)
{
	struct vm *vm = vcpu->vm;
	int ret, state = vm->state;

	if (!vcpu || !desc)
		return -EINVAL;

	/*
	 * Only check the VM's state here, the vcpu's state will check
	 * in kick_vcpu and return_to_user.
	 */
	if ((state != VM_STATE_ONLINE) && (state != VM_STATE_SUSPEND)) {
		pr_warn("VM %s is offline or reboot drop virq %d\n",
				vm->name, desc->vno);
		return -EPERM;
	}

	/*
	 * check the state of the vm, if the vm is in suspend state
	 * and the irq can not wake up the vm, just return. Otherwise
	 * need to kick the vcpu, kick_vcpu can wakeup the system.
	 */
	if ((vm->state == VM_STATE_SUSPEND) && !virq_can_wakeup(desc)) {
		pr_warn("VM %s is suspend drop virq %d\n", vm->name, desc->vno);
		return -EAGAIN;
	}

	// 实际的 send virq 函数
	ret = __send_virq(vcpu, desc);
	if (ret) {
		pr_warn("send virq to vcpu-%d-%d failed\n",
				get_vmid(vcpu), get_vcpu_id(vcpu));
		return ret;
	}

	virq_kick_vcpu(vcpu, desc);

	return 0;
}

// hw 类型的 virq 将会注册到 hyp，注册时的 handler 便为此 guest_irq_handler，它会将中断路由到某具体的 vcpu
static int guest_irq_handler(uint32_t irq, void *data)
{
	struct vcpu *vcpu;
	struct virq_desc *desc = (struct virq_desc *)data;

	if ((!desc) || (!virq_is_hw(desc))) {
		pr_notice("virq %d is not a hw irq\n", desc->vno);
		return -EINVAL;
	}

	/* send the virq to the guest */
	// 如果 vmid 和 vcpu_id 都没有指定，很随便的话，那么就选择当前的 vcpu
	if ((desc->vmid == VIRQ_AFFINITY_VM_ANY) &&
			(desc->vcpu_id == VIRQ_AFFINITY_VCPU_ANY))
		vcpu = get_current_vcpu();
	else
		// 获取 desc 对应的 vcpu
		vcpu = get_vcpu_by_id(desc->vmid, desc->vcpu_id);

	// send virq 给某 vcpu
	return send_virq(vcpu, desc);
}

// 获取中断类型
uint32_t virq_get_type(struct vcpu *vcpu, uint32_t virq)
{
	struct virq_desc *desc;

	desc = get_virq_desc(vcpu, virq);
	if (!desc)
		return 0;

	return desc->type;
}

// 获取中断使能状况
uint32_t virq_get_state(struct vcpu *vcpu, uint32_t virq)
{
	struct virq_desc *desc;

	desc = get_virq_desc(vcpu, virq);
	if (!desc)
		return 0;

	return !!virq_is_enabled(desc);
}

// 获取中断 cpu 亲和性
uint32_t virq_get_affinity(struct vcpu *vcpu, uint32_t virq)
{
	struct virq_desc *desc;

	desc = get_virq_desc(vcpu, virq);
	if (!desc)
		return 0;

	return desc->vcpu_id;
}

// 获取中断优先级
uint32_t virq_get_pr(struct vcpu *vcpu, uint32_t virq)
{
	struct virq_desc *desc;

	desc = get_virq_desc(vcpu, virq);
	if (!desc)
		return 0;

	return desc->pr;
}

// 该 virq 是否可以 request
int virq_can_request(struct vcpu *vcpu, uint32_t virq)
{
	struct virq_desc *desc;

	// 获取对应 virq_desc 结构体
	desc = get_virq_desc(vcpu, virq);
	// 如果为空，virq_desc 以数组的形式存在，这应该是在初始化阶段批量分配的，所以什么时候为空？？？
	if (!desc)
		return 0;

	// 是否设置了可以 request 标志
	return !virq_is_requested(desc);
}

// 需要暴露给外部使用？？？
int virq_need_export(struct vcpu *vcpu, uint32_t virq)
{
	struct virq_desc *desc;

	desc = get_virq_desc(vcpu, virq);
	if (!desc)
		return 0;

	if (desc->flags & VIRQS_NEED_EXPORT)
		return 1;

	return !virq_is_requested(desc);
}

// 设置触发类型
int virq_set_type(struct vcpu *vcpu, uint32_t virq, int value)
{
	struct virq_desc *desc;

	desc = get_virq_desc(vcpu, virq);
	if (!desc)
		return -ENOENT;

	/*
	 * 0 - IRQ_TYPE_LEVEL_HIGH
	 * 1 - IRQ_TYPE_EDGE_RISING
	 */
	if (desc->type != value) {
		desc->type = value;
		//如果是 hardware interrupt，只能设置为特定的值？？？
		if (virq_is_hw(desc)) {
			if (value)
				value = IRQ_FLAGS_EDGE_RISING;
			else
				value = IRQ_FLAGS_LEVEL_HIGH;

			irq_set_type(desc->hno, value);
		}
	}

	return 0;
}

// 设置优先级
int virq_set_priority(struct vcpu *vcpu, uint32_t virq, int pr)
{
	struct virq_desc *desc;

	desc = get_virq_desc(vcpu, virq);
	if (!desc) {
		pr_debug("virq is no exist %d\n", virq);
		return -ENOENT;
	}

	pr_debug("set the pr:%d for virq:%d\n", pr, virq);
	desc->pr = pr;

	return 0;
}

// 设置使能
int virq_enable(struct vcpu *vcpu, uint32_t virq)
{
	struct virq_desc *desc;

	desc = get_virq_desc(vcpu, virq);
	if (!desc)
		return -ENOENT;
	
	//d->flags |= VIRQS_ENABLED;
	virq_set_enable(desc);
	//如果是 spi 类型中断，并且对应着实际的 hardware interrupt，芯片级别 irq_chip->irq_unmask(irq);
	if ((virq > VM_LOCAL_VIRQ_NR) && virq_is_hw(desc))
		irq_unmask(desc->hno);

	return 0;
}

int virq_set_fiq(struct vcpu *vcpu, uint32_t virq)
{
	struct virq_desc *desc;

	desc = get_virq_desc(vcpu, virq);
	if (!desc)
		return -ENOENT;
	// virq_desc 上设置 VIRQS_FIQ 标志
	__virq_set_fiq(desc);

	return 0;
}

int virq_disable(struct vcpu *vcpu, uint32_t virq)
{
	struct virq_desc *desc;

	desc = get_virq_desc(vcpu, virq);
	if (!desc)
		return -ENOENT;

	virq_clear_enable(desc);
	if ((virq > VM_LOCAL_VIRQ_NR) || virq_is_hw(desc))
		irq_mask(desc->hno);

	return 0;
}

int send_virq_to_vcpu(struct vcpu *vcpu, uint32_t virq)
{
	return send_virq(vcpu, get_virq_desc(vcpu, virq));
}

// 发送 virq 给某个 vm
int send_virq_to_vm(struct vm *vm, uint32_t virq)
{
	struct virq_desc *desc;

	/*
	 * only can send SPI virq in this function
	 * if sending virq to dedicate vcpu please
	 * use send_virq_to_vcpu()
	 */
	if ((!vm) || (virq < VM_LOCAL_VIRQ_NR))
		return -EINVAL;

	desc = get_virq_desc(vm->vcpus[0], virq);
	if (!desc)
		return -ENOENT;

	if (!virq_is_enabled(desc)) {
		pr_err("virq%d for %s is not enabled, drop it\n",
				virq, vm->name);
		return -EAGAIN;
	}

	if (virq_is_hw(desc)) {
		pr_err("can not send hw irq in here %d\n", virq);
		return -EPERM;
	}

	return send_virq(get_vcpu_in_vm(vm, desc->vcpu_id), desc);
}

void send_vsgi(struct vcpu *sender, uint32_t sgi, cpumask_t *cpumask)
{
	int cpu;
	struct vcpu *vcpu;
	struct vm *vm = sender->vm;
	struct virq_desc *desc;

	for_each_set_bit(cpu, cpumask->bits, vm->vcpu_nr) {
		vcpu = vm->vcpus[cpu];
		desc = get_virq_desc(vcpu, sgi);
		send_virq(vcpu, desc);
	}
}

void clear_pending_virq(struct vcpu *vcpu, uint32_t irq)
{
	struct virq_struct *virq_struct = vcpu->virq_struct;
	struct virq_desc *desc;

	desc = get_virq_desc(vcpu, irq);
	if ((!desc) || (desc->state != VIRQ_STATE_ACTIVE))
		return;

	/*
	 * this function can only called by the current
	 * running vcpu and excuted on the related pcpu
	 *
	 * check wether the virq is pending agagin, if yes
	 * do not delete it from the pending list, instead
	 * of add it to the tail of the pending list
	 *
	 */
	clear_bit(irq, virq_struct->active_bitmap);
	desc->state = VIRQ_STATE_INACTIVE;
	virqchip_update_virq(vcpu, desc, VIRQ_ACTION_CLEAR);
}

// 从 virq_struct->pending_bitmap 获取 irq
uint32_t get_pending_virq(struct vcpu *vcpu)
{
	struct virq_struct *virq_struct = vcpu->virq_struct;
	int total_irq = vm_irq_count(vcpu->vm);
	struct virq_desc *desc;
	int bit;

	for_each_set_bit(bit, virq_struct->pending_bitmap, total_irq) {
		if (test_bit(bit, virq_struct->active_bitmap))
			continue;

		desc = get_virq_desc(vcpu, bit);
		desc->state = VIRQ_STATE_ACTIVE;
		atomic_dec(&virq_struct->pending_virq);
		clear_bit(bit, virq_struct->pending_bitmap);

		set_bit(bit, virq_struct->active_bitmap);
		virq_struct->active_virq++;

		return bit;
	}

	return BAD_IRQ;
}

// vcpu 是否有 irq 正处于 pending 或者 active 状态中
int vcpu_has_irq(struct vcpu *vcpu)
{
	struct virq_struct *vs = vcpu->virq_struct;
	// vm->vspi_nr + VM_LOCAL_VIRQ_NR
	int total = vm_irq_count(vcpu->vm);
	int pend, active;

	// 查找 pending 位图
	pend = find_first_bit(vs->pending_bitmap, total);
	// 查找 active 位图
	active = find_first_bit(vs->active_bitmap, total);

	// 第一个 irq 的 number 应该要小于总数
	return (pend < total) || (active < total);
}

// 更新 virq 的 一些标志信息
static void update_virq_cap(struct virq_desc *desc, unsigned long flags)
{	
	// 在 desc 级别设置 flags
	desc->flags |= flags;

	// 如果标志带有使能，且该 virq 是一个 hardware interrupt，做芯片级别 unmask
	if ((flags & VIRQF_ENABLE) && virq_is_hw(desc))
		irq_unmask(desc->hno);
	
	// 如果是一个 fiq，在 desc 级别设置 VIRQS_FIQ 标志
	if (flags & VIRQF_FIQ)
		__virq_set_fiq(desc);
}

// virq_struct 初始化
void vcpu_virq_struct_init(struct vcpu *vcpu)
{
	struct virq_struct *virq_struct = vcpu->virq_struct;
	struct virq_desc *desc;
	int i;

	virq_struct->active_virq = 0;
	atomic_set(0, &virq_struct->pending_virq);

	// 所有 desc 重置清零，设置为 0
	memset(&virq_struct->local_desc, 0,
		sizeof(struct virq_desc) * VM_LOCAL_VIRQ_NR);

	// 初始化每个 desc，所欲字段设置为默认值
	for (i = 0; i < VM_LOCAL_VIRQ_NR; i++) {
		desc = &virq_struct->local_desc[i];
		virq_clear_hw(desc);
		virq_set_enable(desc);

		/* this is just for ppi or sgi */
		desc->vcpu_id = VIRQ_AFFINITY_VCPU_ANY;
		desc->vmid = VIRQ_AFFINITY_VM_ANY;
		desc->vno = i;
		desc->hno = 0;
		desc->id = VIRQ_INVALID_ID;
		desc->state = VIRQ_STATE_INACTIVE;
	}
}

// 重置 virq_struct
void vcpu_virq_struct_reset(struct vcpu *vcpu)
{
	struct virq_struct *vs = vcpu->virq_struct;

	memset(vs->pending_bitmap, 0, BITMAP_SIZE(vcpu->vm->vspi_nr));
	memset(vs->active_bitmap, 0, BITMAP_SIZE(vcpu->vm->vspi_nr));
	memset(vs->lrs_bitmap, 0, BITMAP_SIZE(vs->nr_lrs));
	vcpu_virq_struct_init(vcpu);
}

// 注册 virq
static int __request_virq(struct vcpu *vcpu, struct virq_desc *desc,
			uint32_t virq, uint32_t hwirq, unsigned long flags)
{
	if (test_and_set_bit(VIRQS_REQUESTED_BIT,
				(unsigned long *)&desc->flags)) {
		pr_warn("virq-%d may has been requested\n", virq);
		return -EBUSY;
	}

	// 设置 desc 字段值
	desc->vno = virq;  // virq
	desc->hno = hwirq; // hwirq
	desc->vcpu_id = get_vcpu_id(vcpu); // vcpu_id
	desc->pr = 0xa0; // 优先级
	desc->vmid = get_vmid(vcpu); // vmid
	desc->id = VIRQ_INVALID_ID; // LR 编号，send_virq 的时候分配
	desc->state = VIRQ_STATE_INACTIVE; // 刚注册，inactive

	/* mask the bits in spi_irq_bitmap, if it is a SPI */
	// 如果大于 VM_LOCAL_VIRQ_NR，则为 SPI 类型的中断
	if (virq >= VM_LOCAL_VIRQ_NR)
		set_bit(VIRQ_SPI_OFFSET(virq), vcpu->vm->vspi_map);

	/* if the virq affinity to a hwirq need to request
	 * the hw irq */
	// 如果有对应的 hwirq
	if (hwirq) {
		// 设置芯片级别的 cpu 亲和性
		irq_set_affinity(hwirq, vcpu_affinity(vcpu));
		// 设置 VIRQS_HW 标志
		virq_set_hw(desc);
		// 在 hyp 下注册 hwirq 中断
		request_irq(hwirq, guest_irq_handler, IRQ_FLAGS_VCPU,
				vcpu->task->name, (void *)desc);
		irq_mask(desc->hno);
	// 否则清除 desc 的 VIRQS_HW 标志
	} else {
		virq_clear_hw(desc);
	}

	// 更新 virq 的 一些标志信息
	update_virq_cap(desc, flags);

	return 0;
}

// 注册中断的一个衍生函数
int request_virq_affinity(struct vm *vm, uint32_t virq, uint32_t hwirq,
			int affinity, unsigned long flags)
{
	struct vcpu *vcpu;
	struct virq_desc *desc;

	// 获取 vcpu0，这里的 affinity 其实就是一个 vcpu_id
	vcpu = get_vcpu_in_vm(vm, affinity);
	if (!vcpu) {
		pr_err("request virq fail no vcpu-%d in vm-%d\n",
				affinity, vm->vmid);
		return -EINVAL;
	}

	// 获取对应的 desc
	desc = get_virq_desc(vcpu, virq);
	if (!desc) {
		pr_err("virq-%d not exist vm-%d", virq, vm->vmid);
		return -ENOENT;
	}

	// 注册中断
	return __request_virq(vcpu, desc, virq, hwirq, flags);
}

// 查询 vm 支持的最大终端数
static inline int vm_max_virq_line(struct vm *vm)
{
	return (vm_is_host_vm(vm) ? MAX_HVM_VIRQ : MAX_GVM_VIRQ);
}

// 注册中断衍生函数
int request_hw_virq(struct vm *vm, uint32_t virq, uint32_t hwirq,
			unsigned long flags)
{
	if (virq >= vm_max_virq_line(vm)) {
		pr_err("invaild virq-%d for vm-%d\n", virq, vm->vmid);
		return -EINVAL;
	} else {
		// 默认将所有的中断都发送给 vcpu0
		return request_virq_affinity(vm, virq, hwirq, 0, flags);
	}
}

// 注册普通的 virq
int request_virq(struct vm *vm, uint32_t virq, unsigned long flags)
{	
	// hwirq 设置为 0，该 virq 没有与物理物理中断关联
	return request_hw_virq(vm, virq, 0, flags);
}

// 注册 percpu 类型的 virq
int request_virq_pervcpu(struct vm *vm, uint32_t virq, unsigned long flags)
{
	int ret;
	struct vcpu *vcpu;
	struct virq_desc *desc;

	if (virq >= VM_LOCAL_VIRQ_NR)
		return -EINVAL;
	
	// 遍历该 vm 中的所有 vcpu
	vm_for_each_vcpu(vm, vcpu) {
		// 获取 desc
		desc = get_virq_desc(vcpu, virq);
		if (!desc)
			continue;
		
		// 注册中断
		ret = __request_virq(vcpu, desc, virq, 0, flags);
		if (ret) {
			pr_err("request percpu virq-%d failed vm-%d\n",
					virq, vm->vmid);
		}

		/*
		 * Fix me here may need to update the affinity for
		 * thie virq if it is a ppi or sgi, if the ppi is
		 * bind to the hw ppi, need to do this, otherwise
		 * do not need to change it
		 */
		
		desc->vcpu_id = VIRQ_AFFINITY_VCPU_ANY;
		desc->vmid = VIRQ_AFFINITY_VM_ANY;
	}

	return 0;
}

// 分配一个 virq 号并注册虚拟中断
int alloc_vm_virq(struct vm *vm)
{
	int virq;
	int count = vm->vspi_nr;

	HVM_IRQ_LOCK(vm);
	// 在 vspi_map 寻找下一个可用的 virq
	virq = find_next_zero_bit_loop(vm->vspi_map, count, 0);
	// 如果 virq 在范围内，注册该中断
	if (virq < count)
		request_virq(vm, virq + VM_LOCAL_VIRQ_NR, VIRQF_NEED_EXPORT);
	else
		virq = -1;
	HVM_IRQ_UNLOCK(vm);

	// 返回修正后的 virq number，spi 的 id 需要加上 VM_LOCAL_VIRQ_NR 才是该 vm 内全局的 virq
	return (virq >= 0 ? virq + VM_LOCAL_VIRQ_NR : -1);
}

// 释放掉该 virq，即清零相应的位图
void release_vm_virq(struct vm *vm, int virq)
{
	struct virq_desc *desc;

	// 减去 VM_LOCAL_VIRQ_NR
	virq = VIRQ_SPI_OFFSET(virq);
	if (virq >= vm->vspi_nr)
		return;

	HVM_IRQ_LOCK(vm);
	desc = &vm->vspi_desc[virq];
	memset(desc, 0, sizeof(struct virq_desc));
	clear_bit(virq, vm->vspi_map);
	HVM_IRQ_UNLOCK(vm);
}

// 初始化 vm 的 virq 信息
static int virq_create_vm(void *item, void *args)
{
	uint32_t size, vdesc_size, vdesc_bitmap_size, status_bitmap_size;
	struct vm *vm = (struct vm *)item;
	struct virq_struct *vs;
	void *base;
	int i;

	/*
	 * Total size:
	 * 1 - sizeof(struct virq_desc) * vspi_nr
	 * 3 - vitmap_size(spi_nr)
	 * 2 - vcpu_nr * bitmap_size * (SGI + PPI + SPI) * 2
	 */
	// 获取最大的 vspi 数量
	vm->vspi_nr = vm_max_virq_line(vm);
	// 计算需要的 virq_desc 大小
	vdesc_size = sizeof(struct virq_desc) * vm->vspi_nr;
	// 对齐
	vdesc_size = BALIGN(vdesc_size, sizeof(unsigned long));
	// 根据数量 vspi_nr 计算位图大小
	vdesc_bitmap_size = BITMAP_SIZE(vm->vspi_nr);
	// 计算一个位图大小
	// 包括所有类型的中断：PPI+SGI+SPI
	status_bitmap_size = BITMAP_SIZE(vm->vspi_nr + VM_LOCAL_VIRQ_NR);

	// 需要分配的总大小 = virq_descs + spi_bitmap + pending_bitmap + active_bitmap
	size = vdesc_size + vdesc_bitmap_size +
		(status_bitmap_size * vm->vcpu_nr * 2);
	size = PAGE_BALIGN(size);

	pr_notice("allocate 0x%x bytes for virq struct\n", size);
	// 根据大小分配内存
	base = get_free_pages(PAGE_NR(size));
	if (!base) {
		pr_err("no more page for virq struct\n");
		return -ENOMEM;
	}
	// 相关地址信息记录到 vm 对应字段
	memset(base, 0, size);
	vm->vspi_desc = (struct virq_desc *)base;
	vm->vspi_map = (unsigned long *)(base + vdesc_size);
	// 初始化 vcpu 的 pending 和 active 位图
	base = base + vdesc_size + vdesc_bitmap_size;
	for (i = 0; i < vm->vcpu_nr; i++) {
		vs = vm->vcpus[i]->virq_struct;
		ASSERT(vs != NULL);
		vs->pending_bitmap = base;
		base += status_bitmap_size;
		vs->active_bitmap = base;
		base += status_bitmap_size;
	}

	return 0;
}

// 重置 vm 中所有 virq_desc
void vm_virq_reset(struct vm *vm)
{
	struct virq_desc *desc;
	int i;

	/* reset the all the spi virq for the vm */
	for ( i = 0; i < vm->vspi_nr; i++) {
		desc = &vm->vspi_desc[i];
		virq_clear_enable(desc); //屏蔽该 virq
		desc->pr = 0xa0;   //优先级
		desc->type = 0x0;  
		desc->id = VIRQ_INVALID_ID;
		desc->state = VIRQ_STATE_INACTIVE;

		if (virq_is_hw(desc))  //如果是 hw interrupt
			irq_mask(desc->hno); //芯片级屏蔽
	}
}

// 销毁 vm 的 vspi_desc 
static int virq_destroy_vm(void *item, void *data)
{
	int i;
	struct virq_desc *desc;
	struct vm *vm = (struct vm *)item;

	if (vm->vspi_desc) {
		for (i = 0; i < VIRQ_SPI_NR(vm->vspi_nr); i++) {
			desc = &vm->vspi_desc[i];

			/* should check whether the hirq is pending or not */
			if (virq_is_enabled(desc) && virq_is_hw(desc) &&
					desc->hno > VM_LOCAL_VIRQ_NR)
				irq_mask(desc->hno);
		}

		free_pages(vm->vspi_desc);
	}

	return 0;
}

static int virqs_init(void)
{
	register_hook(virq_create_vm, OS_HOOK_CREATE_VM);
	register_hook(virq_destroy_vm, OS_HOOK_DESTROY_VM);

	return 0;
}
subsys_initcall(virqs_init);
