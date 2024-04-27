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
#include <virt/vmodule.h>
#include <minos/timer.h>
#include <asm/io.h>
#include <asm/reg.h>
#include <asm/trap.h>
#include <minos/timer.h>
#include <minos/irq.h>
#include <minos/sched.h>
#include <virt/virq.h>
#include <virt/os.h>
#include <asm/aarch64_reg.h>

#define REG_CNTCR		0x000
#define REG_CNTSR		0x004
#define REG_CNTCV_L		0x008
#define REG_CNTCV_H		0x00c
#define REG_CNTFID0		0x020

#define REG_CNTVCT_LO		0x08
#define REG_CNTVCT_HI		0x0c
#define REG_CNTFRQ		0x10
#define REG_CNTP_CVAL		0x24
#define REG_CNTP_TVAL		0x28
#define REG_CNTP_CTL		0x2c
#define REG_CNTV_CVAL		0x30
#define REG_CNTV_TVAL		0x38
#define REG_CNTV_CTL		0x3c

#define ACCESS_REG		0x0
#define ACCESS_MEM		0x1

// vitual timer
struct vtimer {
	struct vcpu *vcpu;
	struct timer timer;  // virtual timer 也需要在 host 端有一个软件定时器对应
								// 如果该 vtimer 被用作 EL0/1 的 EL1 Physical Timer
								// 那么 timer 作用不言而喻，需要一个软件定时器来模拟 EL1 物理定时器
								// 如果该 vtimer 被用作保存 EL1 Virtual Timer 上下文
								// 那么也需要一个软件定时器，因为对于该 vcpu 来说，虽然它被换出，但是我们希望其 virtual timer 仍然运作
	int virq;            // 该 vtimer 触发中断后，向对应 vcpu 发送 virq 号中断
	uint32_t cnt_ctl;    // 控制字(使能位、屏蔽位、中断条件位)
	uint64_t cnt_cval;   // Compare Value
	uint64_t freq;       // 频率
};

struct vtimer_context {
	struct vtimer phy_timer;     // minos 用此来模拟实现 EL1 Physical Timer
	struct vtimer virt_timer;    // 主要用作保存 vtimer 上下文的位置
	unsigned long offset;        
};

static int arm_phy_timer_trap(struct vcpu *vcpu,
		int reg, int read, unsigned long *value);

static int vtimer_vmodule_id = INVALID_MODULE_ID;

#define get_access_vtimer(vtimer, c, access)		\
	do {						\
		vtimer = &c->phy_timer;			\
	} while (0)

static void phys_timer_expire_function(unsigned long data)
{
	struct vtimer *vtimer = (struct vtimer *)data;

	vtimer->cnt_ctl |= CNT_CTL_ISTATUS;
	vtimer->cnt_cval = 0;

	//如果未禁止
	if (!(vtimer->cnt_ctl & CNT_CTL_IMASK))
		send_virq_to_vcpu(vtimer->vcpu, vtimer->virq);
}

static void virt_timer_expire_function(unsigned long data)
{
	struct vtimer *vtimer = (struct vtimer *)data;

	/*
	 * just wake up the target vCPU. when switch to
	 * this vcpu, the value of vtimer will restore and
	 * if the irq is not mask, the vtimer will trigger
	 * the hardware irq again.
	 */
	//只是唤醒对应的 vcpu，当上下文切换到对应的 vcpu 时，the vtimer 会触发相应的 hardware irq
	wake(&vtimer->vcpu->vcpu_event);
}

//https://blog.csdn.net/Roland_Sun/article/details/105547271
//恢复 vtimer 的上下文
static void vtimer_state_restore(struct vcpu *vcpu, void *context)
{
	struct vtimer_context *c = (struct vtimer_context *)context;
	struct vtimer *vtimer = &c->virt_timer;
	
	// 停止该 vtimer 对应的 timer，这里？？？
	stop_timer(&vtimer->timer);
	// 恢复 offset、control、cval 寄存器的值
	write_sysreg64(c->offset, ARM64_CNTVOFF_EL2);
	write_sysreg64(vtimer->cnt_cval, ARM64_CNTV_CVAL_EL0);
	write_sysreg32(vtimer->cnt_ctl, ARM64_CNTV_CTL_EL0);
	isb();
}

static void vtimer_state_save(struct vcpu *vcpu, void *context)
{
	struct task *task = vcpu->task;
	struct vtimer_context *c = (struct vtimer_context *)context;
	struct vtimer *vtimer = &c->virt_timer;

	// 读取将要保存的 cval、control、offset 寄存器值
	vtimer->cnt_cval = read_sysreg64(ARM64_CNTV_CVAL_EL0);
	vtimer->cnt_ctl = read_sysreg32(ARM64_CNTV_CTL_EL0);
	write_sysreg32(0, CNTV_CTL_EL0);  //istatus imask enable
	isb();
	// 如果当前任务 停止 or 暂停，直接返回？？？ 不需要保存计时器的值？？？
	if ((task->state == TASK_STATE_STOP) ||
			(task->state == TASK_STATE_SUSPEND))
		return;

	// 如果定时器是使能状态 && 没有被屏蔽
	if ((vtimer->cnt_ctl & CNT_CTL_ENABLE) &&
		!(vtimer->cnt_ctl & CNT_CTL_IMASK)) {
		mod_timer(&vtimer->timer, ticks_to_ns(vtimer->cnt_cval +
				c->offset - boot_tick));
	}
}

//初始化 vtimer_context 中的两个 vtimer
static void vtimer_state_init(struct vcpu *vcpu, void *context)
{
	struct vtimer *vtimer;
	struct arm_virt_data *arm_data = vcpu->vm->arch_data;
	struct vtimer_context *c = (struct vtimer_context *)context;

	// 虚拟计数器 = 物理计数器 - 偏移
	if (get_vcpu_id(vcpu) == 0) {
		vcpu->vm->time_offset = get_sys_ticks();//vtimer的offset设置为当前ticks
		// 如果要 trap EL0/1 对 CNTP_XXX_EL1 的访问，那么 host handler 为 arm_phy_timer_trap
		arm_data->phy_timer_trap = arm_phy_timer_trap;
	}

	c->offset = vcpu->vm->time_offset;  // offset 为所属 vm 启动时间

	vtimer = &c->virt_timer;
	vtimer->vcpu = vcpu;
	vtimer->virq = vcpu->vm->vtimer_virq;  // 27
	vtimer->cnt_ctl = 0;
	vtimer->cnt_cval = 0;
	init_timer(&vtimer->timer, virt_timer_expire_function,
			(unsigned long)vtimer);

	vtimer = &c->phy_timer;
	vtimer->vcpu = vcpu;
	vtimer->virq = 26;     // 物理定时器的 irq 默认为 26
	vtimer->cnt_ctl = 0;
	vtimer->cnt_cval = 0;
	init_timer(&vtimer->timer, phys_timer_expire_function,
			(unsigned long)vtimer);
}

//停止对应的两 vtimer
static void vtimer_state_stop(struct vcpu *vcpu, void *context)
{
	struct vtimer_context *c = (struct vtimer_context *)context;

	stop_timer(&c->virt_timer.timer);
	stop_timer(&c->phy_timer.timer);
}

//处理 Counter-timer Physical Timer Control register
static inline void
asoc_handle_cntp_ctl(struct vcpu *vcpu, struct vtimer *vtimer)
{
	/*
	 * apple xnu use physical timer's interrupt as a fiq
	 * and read the ctl register to check wheter the timer
	 * is triggered, if the read access is happened in the
	 * fiq handler, need to clear the interrupt
	 */
	//将 istatus 清零
	//取消该 irq 的 pending 状态
	if ((vtimer->cnt_ctl & CNT_CTL_ISTATUS) &&
			(read_sysreg(HCR_EL2) & HCR_EL2_VF)) {
		vtimer->cnt_ctl &= ~CNT_CTL_ISTATUS;
		clear_pending_virq(vcpu, vtimer->virq);
	}
}

// CNTP_CTL_EL0, Counter-timer Physical Timer Control register
// Control register for the EL1 physical timer.
// 写的情况：控制使能
static void vtimer_handle_cntp_ctl(struct vcpu *vcpu, int access,
		int read, unsigned long *value)
{
	uint32_t v;
	struct vtimer *vtimer;
	struct vtimer_context *c;
	unsigned long ns;

	//获取对应的 phys_timer
	c = get_vmodule_data_by_id(vcpu, vtimer_vmodule_id);
	get_access_vtimer(vtimer, c, access);

	if (read) {
		*value = vtimer->cnt_ctl;
		if (vcpu->vm->os->type == OS_TYPE_XNU)
			asoc_handle_cntp_ctl(vcpu, vtimer);
	} else {
		// 获取使能情况，正常情况总是使能的
		v = (uint32_t)(*value);
		v &= ~CNT_CTL_ISTATUS;

		// enable 使能的情况下，status 的值才有意义
		if (v & CNT_CTL_ENABLE)
			v |= vtimer->cnt_ctl & CNT_CTL_ISTATUS;
		vtimer->cnt_ctl = v;

		// 根据使能状况 重启或者停止 vtimer
		if ((vtimer->cnt_ctl & CNT_CTL_ENABLE) &&
				(vtimer->cnt_cval != 0)) {
			ns = ticks_to_ns(vtimer->cnt_cval + c->offset);
			mod_timer(&vtimer->timer, ns);
		} else {
			stop_timer(&vtimer->timer);
		}
	}
}

// CNTP_TVAL_EL0, Counter-timer Physical Timer TimerValue register
// Holds the timer value for the EL1 physical timer.

//第一种工作方式：到一个绝对时间之后就触发
//比较寄存器有64位，如果设置了之后，当系统计数器达到或超过了这个值之后（CVAL<系统计数器），就会触发定时器中断
static void vtimer_handle_cntp_tval(struct vcpu *vcpu,
		int access, int read, unsigned long *value)
{
	struct vtimer *vtimer;
	unsigned long now;
	unsigned long ticks;
	struct vtimer_context *c;

	c = get_vmodule_data_by_id(vcpu, vtimer_vmodule_id);
	get_access_vtimer(vtimer, c, access);

	// 虚拟机的时间： Now
	now = get_sys_ticks() - c->offset;

	if (read) {
		// vtimer->cnt_cval - get_sys_ticks()，表示距离 timer 触发还剩下多少时间
		ticks = (vtimer->cnt_cval - now - c->offset) & 0xffffffff;
		*value = ticks;
	} else {
		unsigned long v = *value;

		vtimer->cnt_cval = get_sys_ticks() + v;  //当前值+比较值
		if (vtimer->cnt_ctl & CNT_CTL_ENABLE) {
			vtimer->cnt_ctl &= ~CNT_CTL_ISTATUS;  //清除该位，表示触发timer的条件没到
			ticks = ticks_to_ns(vtimer->cnt_cval);
			mod_timer(&vtimer->timer, ticks);   //重启timer
		}
	}
}

// CNTP_CVAL_EL0, Counter-timer Physical Timer CompareValue register
// Holds the compare value for the EL1 physical timer.

//第二种工作模式：从现在开始再过一定时间间隔之后触发
//定时寄存器有32位，如果设置了之后，会将比较寄存器设置成当前系统计数器加上设置的定时寄存器的值（CVAL=系统计数器+TVAL），后面就一样了，当系统计数器达到或超过了这个值后，就会触发定时中断
static void vtimer_handle_cntp_cval(struct vcpu *vcpu,
		int access, int read, unsigned long *value)
{
	unsigned long ns;
	struct vtimer *vtimer;
	struct vtimer_context *c;

	c = get_vmodule_data_by_id(vcpu, vtimer_vmodule_id);
	get_access_vtimer(vtimer, c, access);

	if (read) {
		*value = vtimer->cnt_cval - c->offset;
	} else {
		// value+虚拟机启动时间
		// 感觉这像是一个固定的值
		vtimer->cnt_cval = *value + c->offset;  
		if (vtimer->cnt_ctl & CNT_CTL_ENABLE) {
			vtimer->cnt_ctl &= ~CNT_CTL_ISTATUS;
			ns = ticks_to_ns(vtimer->cnt_cval);
			mod_timer(&vtimer->timer, ns);
		}
	}
}

//switch case handler
static int arm_phy_timer_trap(struct vcpu *vcpu,
		int reg, int read, unsigned long *value)
{
	switch (reg) {
	case ESR_SYSREG_CNTP_CTL_EL0:
		vtimer_handle_cntp_ctl(vcpu, ACCESS_REG, read, value);
		break;
	case ESR_SYSREG_CNTP_CVAL_EL0:
		vtimer_handle_cntp_cval(vcpu, ACCESS_REG, read, value);
		break;
	case ESR_SYSREG_CNTP_TVAL_EL0:
		vtimer_handle_cntp_tval(vcpu, ACCESS_REG, read, value);
		break;
	default:
		break;
	}

	return 0;
}

static int vtimer_vmodule_init(struct vmodule *vmodule)
{
	vmodule->context_size = sizeof(struct vtimer_context);
	vmodule->state_init = vtimer_state_init;
	vmodule->state_save = vtimer_state_save;
	vmodule->state_restore = vtimer_state_restore;
	vmodule->state_stop = vtimer_state_stop;
	vmodule->state_reset = vtimer_state_stop;
	vtimer_vmodule_id = vmodule->id;

	return 0;
}

int arch_vtimer_init(uint32_t virtual_irq, uint32_t phy_irq)
{
	return register_vcpu_vmodule("vtimer_module", vtimer_vmodule_init);
}

int virtual_timer_irq_handler(uint32_t irq, void *data)
{
	uint32_t value;
	struct vcpu *vcpu = get_current_vcpu();

	/*
	 * if the current task is not a vcpu, disable the vtimer
	 * since the pending request vtimer irq is set to
	 * the timer
	 */
	if (!task_is_vcpu(current)) {
		write_sysreg32(0, ARM64_CNTV_CTL_EL0);
		return 0;
	}

	/*
	 * this case ususally happened when the vcpu called
	 * WFI to enter idle idle mode, but the vtimer irq is
	 * triggered when context switch. then when in idle task
	 * this IRQ is responsed. two case need consider:
	 *
	 * 1 - the vtimer interrup will send to wrong vcpu ?
	 * 2 - Here the logic of idle can be optimized to avoid
	 *     this situation
	 */
	//也就是说，正常情况下，进入 handler 处理时钟中断的时候，istatus = 1
	value = read_sysreg32(ARM64_CNTV_CTL_EL0);
	if (!(value & CNT_CTL_ISTATUS)) {
		pr_debug("vtimer is not trigger\n");
		return 0;
	}

	//禁止该 vtimer
	value = value | CNT_CTL_IMASK;
	write_sysreg32(value, ARM64_CNTV_CTL_EL0);

	//发送 virq 给对应的 vcpu
	//vcpu对应的vtimer的中断号记录在 vcpu->vm->vtimer_virq
	return send_virq_to_vcpu(vcpu, vcpu->vm->vtimer_virq);
}
