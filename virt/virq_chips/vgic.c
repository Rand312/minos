/*
 * Copyright (C) 2018 - 2019 Min Le (lemin9538@gmail.com)
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
#include <virt/virq.h>
#include <virt/virq_chip.h>
#include <minos/of.h>
#include <libfdt/libfdt.h>

// TODO 下面这几种情况具体含义

/*
 * The following cases are considered software programming
 * errors and result in UNPREDICTABLE behavior:
 *
 * • Having a List register entry with ICH_LR<n>_EL2.HW= 1
 *   which is associated with a physical interrupt, inactive
 *   state or in pending state in the List registers if the
 *   Distributor does not have the corresponding physical
 *   interrupt in either the active state or the active and
 *   pending state.
 * • If ICC_CTLR_EL1.EOImode == 0 or ICC_CTLR_EL3.EOImode_EL3 == 0
 *   then either:
 *   — Having an active interrupt in the List registers with a priorit
 *   that is not set in the corresponding Active Priorities Register.
 *   — Having two interrupts in the List registers in the active stat
 *   with the same preemption priority.>
 * • Having two or more interrupts with the same pINTID in the Lis
 *   registers for a single virtual CPU interface.
 */



// 进入 guest 
int vgic_irq_enter_to_guest(struct vcpu *vcpu, void *data)
{
	struct virq_struct *vs = vcpu->virq_struct;
	struct vm *vm = vcpu->vm;
	struct virq_desc *virq;
	int id = 0, bit, flags = 0, size, old;

	bit = vs->last_fail_virq;
	size = vm_irq_count(vm) - bit;
	old = vs->last_fail_virq;
	vs->last_fail_virq = 0;

repeat:
	// 遍历该 vcpu 的 pending_map
	for_each_set_bit_from(bit, vs->pending_bitmap, size) {
		// 获取该 virq 对应的 virq_desc
		virq = get_virq_desc(vcpu, bit);
		if (virq == NULL) {
			pr_err("bad virq %d for vm %s\n", bit, vm->name);
			clear_bit(bit, vs->pending_bitmap);
			continue;
		}

		/*
		 * do not send this virq if there is same virq in
		 * active state, need wait the previous virq done.
		 */
		// 如果它也存在于 active_map，continue
		// 说明这里处理 pending_and_active 中断的方式是不重复 trigger
		if (test_bit(bit, vs->active_bitmap))
			continue;

		/* allocate a id for the virq */
		// 分配一个 LR 寄存器
		id = find_first_zero_bit(vs->lrs_bitmap, vs->nr_lrs);
		// 分配失败
		if (id >= vs->nr_lrs) {
			pr_err("VM%d no space to send new irq %d\n",
					vm->vmid, virq->vno);
			// 记录分配 LR 失败的 virq
			vs->last_fail_virq = bit;
			break;
		}

		/*
		 * indicate that FIQ has been inject.
		 */
		// 将要注入 FIQ，记录下标志
		if (virq->flags & VIRQS_FIQ)
			flags |= FIQ_HAS_INJECT;
		flags++;
		virq->id = id;   // 设置刚分配的 lr_id
		set_bit(id, vs->lrs_bitmap);
		
		// 芯片级别 send_virq，核心是写 gich_lr 寄存器
		virqchip_send_virq(vcpu, virq);
		// 状态转移
		virq->state = VIRQ_STATE_PENDING;

		/*
		 * mark this virq as pending state and add it
		 * to the active bitmap.
		 */
		// 设置为 active
		set_bit(bit, vs->active_bitmap);
		vs->active_virq++;

		/*
		 * remove this virq from pending bitmap.
		 */
		// pending_nr --
		atomic_dec(&vs->pending_virq);
		// 清除在 pending map 中的比特位
		clear_bit(bit, vs->pending_bitmap);
	}

	// old ！= 0 表示上次想要 send virq 时，但是没有空闲的 lr 寄存器了，且发送失败的 virq 号记录到了 bit
	// vs->last_fail_virq == 0 表示这次很可能有空闲的 lr 寄存器
	// 所以调整 size 为上次失败的 virq 号，让上面的循环能够触及该失败的 virq 号，且为其分配 lr 寄存器
	if ((old != 0) && (vs->last_fail_virq == 0)) {
		bit = 0;
		size = old;
		old = 0;
		goto repeat;
	}

	return flags;
}

// 退出 guest
int vgic_irq_exit_from_guest(struct vcpu *vcpu, void *data)
{
	struct virq_struct *vs = vcpu->virq_struct;
	struct virq_desc *virq;
	int bit;

	// 遍历该 vcpu 所有的 active_bitmap，这也就是说，可能出现多个 active interrupt
	for_each_set_bit(bit, vs->active_bitmap, vm_irq_count(vcpu->vm)) {
		// 获取对应的 virq_desc
		virq = get_virq_desc(vcpu, bit);
		if (virq == NULL) {
			pr_err("bad active virq %d\n", virq);
			clear_bit(bit, vs->active_bitmap);
			continue;
		}

		/*
		 * the virq has been handled by the VCPU, if
		 * the virq is not pending again, delete it
		 * otherwise add the virq to the pending list
		 * again
		 */
		// 获取状态
		virq->state = virqchip_get_virq_state(vcpu, virq);
		// 如果该 virq 已经是 inactive，说明已处理完成
		// 重置 virq 对应的 LR 为空闲状态
		if (virq->state == VIRQ_STATE_INACTIVE) {
			virqchip_update_virq(vcpu, virq, VIRQ_ACTION_CLEAR);
			clear_bit(virq->id, vs->lrs_bitmap);
			virq->id = VIRQ_INVALID_ID;
			vs->active_virq--;
			clear_bit(bit, vs->active_bitmap);
		}
	}

	return 0;
}

// 
int vgic_generate_virq(uint32_t *array, int virq)
{
	array[0] = cpu_to_fdt32(0x0);
	array[1] = cpu_to_fdt32(virq - 32);
	array[2] = cpu_to_fdt32(0x4);

	return 3;
}

static int virq_chip_vcpu_init(void *item, void *contex)
{
	struct vcpu *vcpu = (struct vcpu *)item;
	struct virq_chip *vc = vcpu->vm->virq_chip;

	if (vc && vc->vcpu_init)
		return vc->vcpu_init(vcpu, vc->inc_pdata, vc->flags);

	return 0;
}

static int __init_text vcpu_vgic_hook_init(void)
{
	return register_hook(virq_chip_vcpu_init, OS_HOOK_VCPU_INIT);
}
module_initcall(vcpu_vgic_hook_init);
