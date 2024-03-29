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
#include <minos/percpu.h>
#include <minos/sched.h>
#include <minos/mm.h>

// 定义物理 cpu
struct pcpu pcpus[NR_CPUS];
unsigned long __cache_line_align percpu_offset[CONFIG_NR_CPUS];

#define PCPU_STAT_OFFLINE	0
#define PCPU_STAT_ONLINE	1

// 初始化 percpu_offset 值，方便后面通过 get_per_cpu 宏来获取 percpu 值
void percpu_init(int cpuid)
{
	extern unsigned char __percpu_start;
	extern unsigned char __percpu_section_size;
	int i;

	/*
	 * the data of percpu section has been zeroed at boot code
	 * here do not to zero it again.
	 *
	 * some member of pcpu has been init on boot stage, like cpuid.
	 */

	// percpu 的原理就是单个 cpu 所有的私有数据存放在一起，然后再存放下一个 cpu 所有的数据
	// 所有对于不同 cpu 的同一个数据，有一个 offset
	// 这个 offset 就是一个 cpu 所有私有数据的集合大小
	// __percpu_section_size = __percpu_cpu_0_end - __percpu_cpu_0_start;
	for (i = 0; i < CONFIG_NR_CPUS; i++) {
		percpu_offset[i] = (phy_addr_t)(&__percpu_start) +
			(size_t)(&__percpu_section_size) * i;
		pr_info("percpu [%d] offset 0x%x\n", i, percpu_offset[i]);
		get_per_cpu(pcpu, i) = &pcpus[i];
	}
}

// 给每个 cpu 分配 stack
static int percpu_subsystem_init(void)
{
	struct pcpu *pcpu = get_pcpu();
	// 分配 stack 内存
	pcpu->stack = get_free_pages(2);
	ASSERT(pcpu->stack != NULL);
	// 移动到栈顶
	pcpu->stack += 2 * PAGE_SIZE;
	pcpu->state = PCPU_STATE_RUNNING;

	return 0;
}
subsys_initcall_percpu(percpu_subsystem_init);
