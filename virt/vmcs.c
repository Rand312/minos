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
#include <minos/sched.h>
#include <virt/virq.h>
#include <minos/irq.h>
#include <virt/vmcs.h>

int __vcpu_trap(uint32_t type, uint32_t reason, unsigned long data,
		unsigned long *result, int nonblock)
{
	unsigned long flags;
	struct vcpu *vcpu = get_current_vcpu();
	struct vmcs *vmcs = vcpu->vmcs;
	struct vm *vm0 = get_host_vm();

	if (vcpu->vmcs_irq < 0) {
		pr_err("no hvm irq for this vcpu\n");
		return -ENOENT;
	}

	if ((type >= VMTRAP_TYPE_UNKNOWN) ||
			(reason >= VMTRAP_REASON_UNKNOWN))
		return -EINVAL;

	/*
	 * enable the interrupt in case the vm0 shutdown
	 * or reboot this vm when the vm is waitting for
	 * vmcs ack
	 */
	local_irq_save(flags);
	local_irq_enable();

	/*
	 * wait for the last trap complete, if the gvm
	 * has the same affinity pcpu with the vm0, need
	 * to use sched() in case of dead lock
	 */
	while (vmcs->guest_index != vmcs->host_index) {
		if (vcpu_affinity(vcpu) < vcpu_affinity(vm0->vcpus[0]))
			sched();
		else
			cpu_relax();
		mb();

		if (is_task_need_stop(current)) {
			local_irq_restore(flags);
			pr_err("vcpu need stop, exit %s\n", __func__);
			return -EABORT;
		}
	}

	vmcs->trap_type = type;
	vmcs->trap_reason = reason;
	vmcs->trap_data = data;
	vmcs->trap_ret = 0;
	vmcs->trap_result = result ? *result : 0;
	smp_mb();

	/*
	 * increase the host index of the vmcs, then send the
	 * virq to the vcpu0 of the vm0
	 */
	vmcs->host_index++;
	smp_mb();

	if (send_virq_to_vm(vm0, vcpu->vmcs_irq)) {
		pr_err("vmcs failed to send virq for vm-%d\n",
				vcpu->vm->vmid);
		vmcs->host_index--;
		smp_mb();

		vmcs->trap_ret = -EPERM;
		vmcs->trap_result = 0;
		return -EFAULT;
	}

	/*
	 * if vcpu's pcpu is equal the vm0_vcpu0's pcpu
	 * force to block
	 */
	if (vcpu_affinity(vcpu) == vcpu_affinity(vm0->vcpus[0]))
		nonblock = 0;

	/*
	 * if gvm's vcpu is on the same pcpu which hvm
	 * affnity, then need to call sched to sched the
	 * hvm's vcpu in case of dead lock
	 */
	if (!nonblock) {
		while (vmcs->guest_index != vmcs->host_index) {
			if (vcpu_affinity(vcpu) < vm0->vcpu_nr)
				sched();
			else
				cpu_relax();

			if (is_task_need_stop(current)) {
				local_irq_restore(flags);
				pr_err("vcpu need stop, exit %s\n", __func__);
				return -EABORT;
			}
		}

		if (result)
			*result = vmcs->trap_result;
	} else {
		if (result)
			*result = 0;
	}

	local_irq_restore(flags);

	return vmcs->trap_ret;
}

int setup_vmcs_data(void *data, size_t size)
{
	void *base = (void *)get_current_vcpu()->vmcs->data;

	if (size > VMCS_DATA_SIZE)
		return -ENOMEM;

	memcpy(base, data, size);
	return 0;
}

static void vcpu_vmcs_init(struct vcpu *vcpu)
{
	struct vmcs *vmcs = vcpu->vmcs;

	if (!vmcs) {
		pr_err("vmcs of vcpu is NULL\n");
		return;
	}

	vmcs->vcpu_id = get_vcpu_id(vcpu);
}

unsigned long vm_create_vmcs(struct vm *vm)
{
	int i;
	uint32_t size;
	struct vcpu *vcpu;
	void *base;
	unsigned long hvm_vmcs;

	if (vm->vmcs || vm->hvm_vmcs)
		return 0;

	size = VMCS_SIZE(vm->vcpu_nr);
	// 从 shmem block 分配内存，这里返回的是 el2 地址
	base = alloc_shmem(PAGE_NR(size));
	if (!base)
		return 0;

	memset(base, 0, size);

	hvm_vmcs = create_hvm_shmem_map(vm, (unsigned long)base, size);
	if (hvm_vmcs == BAD_ADDRESS) {
		pr_err("mapping vmcs to hvm failed\n");
		free_shmem(base);
		return 0;
	}

	for (i = 0; i < vm->vcpu_nr; i++) {
		vcpu = vm->vcpus[i];
		vcpu->vmcs = (struct vmcs *)(base +
				i * sizeof(struct vmcs));
		vcpu_vmcs_init(vcpu);
	}

	return hvm_vmcs;
}

int vm_create_vmcs_irq(struct vm *vm, int vcpu_id)
{
	struct vcpu *vcpu = get_vcpu_in_vm(vm, vcpu_id);

	if (!vcpu)
		return -ENOENT;

	// 在 hvm 中注册一个 virq
	vcpu->vmcs_irq = alloc_hvm_virq();
	if (vcpu->vmcs_irq < 0)
		pr_err("alloc virq for vmcs failed\n");

#ifdef CONFIG_PLATFORM_BCM2837
	return vcpu->vmcs_irq - 32;
#else
	return vcpu->vmcs_irq;
#endif
}
