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
#include <minos/time.h>
#include <minos/init.h>
#include <asm/io.h>
#include <minos/stdlib.h>
#include <minos/softirq.h>
#include <minos/sched.h>
#include <minos/irq.h>
#include <minos/of.h>
#include <asm/reg.h>
#include <minos/platform.h>
#include <asm/aarch64_reg.h>

enum timer_type {
	SEC_PHY_TIMER,
	NONSEC_PHY_TIMER,
	VIRT_TIMER,
	HYP_TIMER,
	TIMER_MAX,
};

static char *timer_name[TIMER_MAX] = {
	"   sec_phy_timer ",
	"nonsec_phy_timer ",
	"      virt_timer ",
	"hypervisor_timer "
};

struct armv8_timer_info {
	uint32_t irq;
	unsigned long flags;
};

static struct armv8_timer_info timer_info[TIMER_MAX];

uint32_t cpu_khz = 0;
uint64_t boot_tick = 0;

extern unsigned long sched_tick_handler(unsigned long data);

// 使能一个 timer，expires 是过期时间，也是一个计数值
// 当 physical counter 的计数大于等于这个过期计数值，触发中断
void arch_enable_timer(unsigned long expires)
{
	uint64_t deadline;
	unsigned long ctl;

	if (expires == 0) {
		write_sysreg32(0, ARM64_CNTSCHED_CTL);
		return;
	}

	// 设置过期时间——Compare Value
	deadline = ns_to_ticks(expires);
	// 将 CompareValue 写入 CNTHP_CVAL_EL2 
	write_sysreg64(deadline, ARM64_CNTSCHED_CVAL);

	ctl = read_sysreg(ARM64_CNTSCHED_CTL);
	ctl |= CNT_CTL_ENABLE;   // 使能
	ctl &= ~CNT_CTL_IMASK;   // 接触屏蔽
	write_sysreg(ctl, ARM64_CNTSCHED_CTL);
	isb();
}

// 读取 physical counter 数值，wall-clock time
 
//Holds the 64-bit physical count value.
unsigned long get_sys_ticks(void)
{
	isb();
	return read_sysreg64(CNTPCT_EL0);
}

//减去 boot 时刻的 ticks，即相对于启机时刻的当前时间
unsigned long get_current_time(void)
{
	isb();
	return ticks_to_ns(read_sysreg64(CNTPCT_EL0) - boot_tick);
}

//将 ticks 转换为 ns
unsigned long get_sys_time(void)
{
	isb();
	return ticks_to_ns(read_sysreg64(CNTPCT_EL0));
}

//初始化 arch 的 timer，主要是从设备树中获取信息
static int __init_text timers_arch_init(void)
{
	int i, ret, from_dt;
	struct armv8_timer_info *info;
	struct device_node *node = NULL;

#ifdef CONFIG_DEVICE_TREE
	node = of_find_node_by_compatible(of_root_node, arm_arch_timer_match_table);
#endif
	if (!node) {
		pr_err("can not find arm-arch-timer\n");
		return -EINVAL;
	}

	for (i = 0; i < TIMER_MAX; i++) {
		info = &timer_info[i];
		//获取设备树中记录的中断号
		ret = get_device_irq_index(node, &info->irq, &info->flags, i);
		if (ret) {
			pr_err("error found in arm timer config\n");
			return -ENOENT;
		}

// [       0.000000@00 000] NIC    sec_phy_timer  : 29
// [       0.000000@00 000] NIC nonsec_phy_timer  : 30
// [       0.000000@00 000] NIC       virt_timer  : 27
// [       0.000000@00 000] NIC hypervisor_timer  : 26
		pr_notice("%s : %d\n", timer_name[i], info->irq);
	}

	// 获取时钟频率
	ret = of_get_u32_array(node, "clock-frequency", &cpu_khz, 1);
	if (cpu_khz > 0) {
		cpu_khz = cpu_khz / 1000;
		from_dt = 1;
	} else {
		cpu_khz = read_sysreg32(CNTFRQ_EL0) / 1000;
		from_dt = 0;
	}

	isb();
	//获取当前的 ticks，记录到 boot_tick
	// Holds the 64-bit physical count value
	boot_tick = read_sysreg64(CNTPCT_EL0);
	pr_notice("clock freq from %s %d\n", from_dt ? "DTB" : "REG", cpu_khz);
	pr_notice("boot ticks is :0x%x\n", boot_tick);

	if (platform->time_init)
		platform->time_init();

#ifdef CONFIG_VIRT
	extern int arch_vtimer_init(uint32_t virtual_irq, uint32_t phy_irq);
	arch_vtimer_init(timer_info[VIRT_TIMER].irq,
			timer_info[NONSEC_PHY_TIMER].irq);
#endif

	return 0;
}

static int timer_interrupt_handler(uint32_t irq, void *data)
{
	extern void soft_timer_interrupt(void);
	unsigned long ctl;

	// 禁止中断
	ctl = read_sysreg(ARM64_CNTSCHED_CTL);
	ctl |= CNT_CTL_IMASK;			// disable the interrupt.
	write_sysreg(ctl, ARM64_CNTSCHED_CTL);

	//处理时钟中断
	soft_timer_interrupt();

	return 0;
}

static int __init_text timers_init(void)
{
	struct armv8_timer_info *sched_timer_info = NULL;

#ifdef CONFIG_VIRT
	struct armv8_timer_info *info;
	extern int virtual_timer_irq_handler(uint32_t irq, void *data);

	// Holds the 64-bit virtual offset. This is the offset between the physical count value visible in CNTPCT_EL0 and the virtual count value visible in CNTVCT_EL0.
	write_sysreg64(0, CNTVOFF_EL2);

	/* el1/el0 can read CNTPCT_EL0 */
	//Counter-timer Hypervisor Control register
	//EL0VCTEN, bit [1]
	//When HCR_EL2.TGE is 0, this control does not cause any instructions to be trapped.
	//When HCR_EL2.TGE is 1, traps EL0 accesses to the frequency register and virtual counter register to EL2.
	write_sysreg32(1 << 0, CNTHCTL_EL2);

	/* disable hyper and phy timer */
	//control register 都有 3bit: istatus imask enable
	//Counter-timer Physical Timer Control register
	write_sysreg32(0, CNTP_CTL_EL0);
	// Counter-timer Hypervisor Physical Timer Control register
	write_sysreg32(0, CNTHP_CTL_EL2);
	isb();

	info = &timer_info[VIRT_TIMER];
	// 注册 virt timer 中断
	if (info->irq) {
		request_irq(info->irq, virtual_timer_irq_handler,
			info->flags & 0xf, "virt timer irq", NULL);
	}

	// 虚拟化的情况下，选取 hyp timer
	sched_timer_info = &timer_info[HYP_TIMER];
#else
	sched_timer_info = &timer_info[VIRT_TIMER];
#endif

	ASSERT(sched_timer_info && sched_timer_info->irq);
	// 注册 hyp timer 中断
	request_irq(sched_timer_info->irq,
			timer_interrupt_handler,
			sched_timer_info->flags & 0xf,
			"sched_timer_int", NULL);

	return 0;
}

subsys_initcall_percpu(timers_init);
subsys_initcall(timers_arch_init);
