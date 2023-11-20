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
#include <config/config.h>
#include <minos/percpu.h>
#include <minos/platform.h>
#include <minos/irq.h>
#include <asm/cache.h>

#define SMP_CALL_LOCKED		(1 << 0)

#define SMP_FUNCTION_CALL_IRQ	CONFIG_SMP_FUNCTION_CALL_IRQ

extern unsigned char __smp_affinity_id;
uint64_t *smp_affinity_id;
phy_addr_t smp_holding_address[CONFIG_NR_CPUS];

cpumask_t cpu_online;
static int cpus_all_up;

// 核间调用
struct smp_call {
	smp_function fn;
	unsigned long flags;
	void *data;
};

struct smp_call_data {
	struct smp_call smp_calls[NR_CPUS];
};

// 每个 CPU 定义一个 smp_call_data，每个 smp_call_data 都是对其他 CPU 的 smp_call
static DEFINE_PER_CPU(struct smp_call_data, smp_call_data);

// wait
static void inline smp_call_wait(struct smp_call *call)
{
	/* need wait for last call finished */
	while (call->flags & SMP_CALL_LOCKED)
		cpu_relax();
}

// 上锁
static void inline smp_call_lock(struct smp_call *call)
{
	if (call->flags & SMP_CALL_LOCKED)
		pr_warn("smp call is already locked\n");

	call->flags |= SMP_CALL_LOCKED;
	wmb();
}

// 解锁
static void inline smp_call_unlock(struct smp_call *call)
{
	call->flags &= ~SMP_CALL_LOCKED;
	wmb();
}

int is_cpus_all_up(void)
{
	return cpus_all_up;
}

// 
int smp_function_call(int cpu, smp_function fn, void *data, int wait)
{
	int cpuid;
	struct smp_call *call;
	struct smp_call_data *cd;
	unsigned long flags;

	// 禁止抢占
	preempt_disable();
	// 当前 cpu id
	cpuid = smp_processor_id();

	if (cpu >= NR_CPUS)
		return -EINVAL;

	/* function call itself just call the function */
	// 向自己发送 call
	if (cpu == cpuid) {
		local_irq_save(flags);
		// 调用对应的 handler
		fn(data);
		local_irq_restore(flags);
		// 开启抢占，然后返回
		preempt_enable();
		return 0;
	}

	// 获取目标 cpu 的 smp_call_data 结构体
	cd = &get_per_cpu(smp_call_data, cpu);
	// 将当前 cpu id 作为 index，获取 smp_call 结构体
	call = &cd->smp_calls[cpuid];

	// “检测” 该 call 是否在使用当中，即不可重入
	smp_call_wait(call);
	// 重新设置该 call 的 handler fn，参数 dta
	call->fn = fn;
	call->data = data;
	// 对该 call 上锁
	smp_call_lock(call);

	// 发送 sgi 中断给 目标cpu
	send_sgi(SMP_FUNCTION_CALL_IRQ, cpu);

	// 如果等待，即同步调用call，那么这里调用 smp_call_wait 等待
	if (wait)
		smp_call_wait(call);
	
	//开启抢占
	preempt_enable();

	return 0;
}

// 这里应当是一个 cpu 收到 sgi 中断后的 handler 函数
// 这里是一次性处理所有发向自己的 sgi
static irqreturn_t smp_function_call_handler(uint32_t irq, void *data)
{
	int i;
	struct smp_call_data *cd;
	struct smp_call *call;

	//获取当前 cpu 的 smp_call_data 结构体
	cd = &get_cpu_var(smp_call_data);
	// 遍历 cpu
	for (i = 0; i < NR_CPUS; i++) {
		// 获取对应的 smp_call 
		call = &cd->smp_calls[i];
		//如果有上锁，那么说明确实有其他 cpu 向自己发送 sgi 中断，那么调用对应的 fn 来处理
		if (call->flags & SMP_CALL_LOCKED) {
			call->fn(call->data);
			call->fn = NULL;
			call->data = NULL;
			// 解锁
			smp_call_unlock(call);
		}
	}

	return 0;
}

// cpu 启动 ？？?
int smp_cpu_up(unsigned long cpu, unsigned long entry)
{
	if (platform->cpu_on)
		return platform->cpu_on(cpu, entry);

	pr_warn("no cpu on function\n");
	return 0;
}

// 启动所有 CPU
void smp_cpus_up(void)
{
	int i, ret, cnt;
	uint64_t affinity;

	// flush 所有 cache 行
	flush_cache_all();
	// 遍历 CPU，然后调用 smp_cpu_up
	for (i = 1; i < CONFIG_NR_CPUS; i++) {
		cnt = 0;
		affinity = cpuid_to_affinity(i);

		ret = smp_cpu_up(affinity, CONFIG_MINOS_ENTRY_ADDRESS);
		if (ret) {
			pr_fatal("failed to bring up cpu-%d\n", i);
			continue;
		}
	}

	for (i = 1; i < CONFIG_NR_CPUS; i++) {
		pr_notice("waiting 2 seconds for cpu-%d up\n", i);
		while ((smp_affinity_id[i] == 0) && (cnt < 2000)) {
			mdelay(1);
			cnt++;
		}

		if (smp_affinity_id[i] == 0) {
			pr_err("cpu-%d is not up with affinity id 0x%p\n",
					i, smp_affinity_id[i]);
		} else {
			cpumask_set_cpu(i, &cpu_online);
		}
	}

	cpus_all_up = 1;
	wmb();
}


void smp_init(void)
{
	int i;
	struct smp_call_data *cd;

	smp_affinity_id = (uint64_t *)&__smp_affinity_id;
	memset(smp_affinity_id, 0, sizeof(uint64_t) * NR_CPUS);

	cpumask_clearall(&cpu_online);
	cpumask_set_cpu(0, &cpu_online);

	for (i = 0; i < NR_CPUS; i++) {
		cd = &get_per_cpu(smp_call_data, i);
		memset(cd, 0, sizeof(struct smp_call_data));
	}

	arch_smp_init(smp_holding_address);

	// 注册 smp call
	request_irq_percpu(SMP_FUNCTION_CALL_IRQ,
			smp_function_call_handler, 0,
			"smp_function_call", NULL);
}
