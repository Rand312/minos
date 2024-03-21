/*
 * Copyright (C) 2019 Min Le (lemin9538@gmail.com)
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
#include <minos/mm.h>
#include <minos/atomic.h>
#include <minos/task.h>

static DEFINE_SPIN_LOCK(tid_lock);
static DECLARE_BITMAP(tid_map, OS_NR_TASKS);
//该 OS 对应的 task table
struct task *os_task_table[OS_NR_TASKS];
static LIST_HEAD(task_list);

/* idle task needed be static defined */
// 定义与 CPU 个数相同的 idle task，这定义的是实际的 task 结构体
struct task idle_tasks[NR_CPUS];
// 这里定义 percpu 数据，是个指针，指向对应的 idle task，在 task_early_init 中设置的
static DEFINE_PER_CPU(struct task *, idle_task);

// 使用do{...}while(0)构造后的宏定义不会受到大括号、分号等的影响，总是会按你期望的方式调用运行
#define TASK_INFO_INIT(__ti, task) 		\
	do {					\
		(__ti)->preempt_count = 0; 	\
		(__ti)->flags = 0;		\
	} while (0)

// 分配 task id
static int alloc_tid(void)
{
	int tid = -1;

	spin_lock(&tid_lock);

	tid = find_next_zero_bit(tid_map, OS_NR_TASKS, 1);
	if (tid >= OS_NR_TASKS)
		tid = -1;
	else
		set_bit(tid, tid_map);

	spin_unlock(&tid_lock);

	return tid;
}

static int request_tid(int tid)
{
	BUG_ON((tid <= 0) || (tid >= OS_NR_TASKS), "no such tid %d\n", tid);
	return !test_and_set_bit(tid, tid_map);
}

static void release_tid(int tid)
{
	ASSERT((tid < OS_NR_TASKS) && (tid > 0));
	os_task_table[tid] = NULL;
	smp_wmb();
	clear_bit(tid, tid_map);
}

static int tid_early_init(void)
{
	/*
	 * tid is reserved for system use.
	 */
	set_bit(0, tid_map);

	return 0;
}
early_initcall(tid_early_init);

// task 时间片到了，
static void task_timeout_handler(unsigned long data)
{
	struct task *task = (struct task *)data;
	// MARK，这是什么意思？？？
	wake_up_timeout(task);
	// 设置 __TIF_NEED_RESCHED 标志，需要 resched，异常返回时检查是否需要 resched
	set_need_resched();
}

static void task_init(struct task *task, char *name,
		void *stack, uint32_t stk_size, int prio,
		int tid, int aff, unsigned long opt, void *arg)
{
	/*
	 * idle task is setup by create_idle task, skip
	 * to setup the stack information of idle task, by
	 * default the kernel stack will set to stack top.
	 */
	// 如果不是 idle task，执行下面的操作
	if (!(opt & TASK_FLAGS_IDLE)) {
		task->stack_bottom = stack;
		task->stack_top = stack + stk_size;
		task->stack_base = task->stack_top;

		TASK_INFO_INIT(&task->ti, task);
	}

	task->tid = tid;
	task->prio = prio;
	task->pend_state = 0;
	task->flags = opt;
	task->pdata = arg;
	task->affinity = aff;
	task->run_time = TASK_RUN_TIME;
	spin_lock_init(&task->s_lock);
	task->state = TASK_STATE_SUSPEND;
	task->cpu = -1;

	init_timer(&task->delay_timer, task_timeout_handler,
			(unsigned long)task);

	os_task_table[tid] =  task;

	if (name)
		strncpy(task->name, name, MIN(strlen(name), TASK_NAME_SIZE));
	else
		sprintf(task->name, "task%d", tid);
}

// 创建一个 task，主要是 task 结构体相关的一些资源
static struct task *do_create_task(char *name,
				  task_func_t func,
				  uint32_t ssize,
				  int prio,
				  int tid,
				  int aff,
				  unsigned long opt,
				  void *arg)
{
	size_t stk_size = PAGE_BALIGN(ssize);
	struct task *task;
	void *stack = NULL;

	/*
	 * allocate the task's kernel stack
	 */
	// 分配一个 task 结构体
	task = zalloc(sizeof(struct task));
	if (!task) {
		pr_err("no more memory for task\n");
		return NULL;
	}
	// 分配栈空间
	stack = get_free_pages(PAGE_NR(stk_size));
	if (!stack) {
		pr_err("no more memory for task stack\n");
		free(task);
		return NULL;
	}

	// 初始化 task 结构体
	task_init(task, name, stack, stk_size, prio, tid, aff, opt, arg);

	return task;
}

static void task_create_hook(struct task *task)
{
	do_hooks((void *)task, NULL, OS_HOOK_CREATE_TASK);
}

// 
void task_exit_from_user(gp_regs *regs)
{
       struct task *task = current;

       ASSERT(task->flags & TASK_FLAGS_VCPU);
       if (task->exit_from_user)
               task->exit_from_user(task, regs);
}

void task_return_to_user(gp_regs *regs)
{
	struct task *task = current;
	unsigned long flags = task->ti.flags;

	ASSERT(current->flags & TASK_FLAGS_VCPU);
	task->ti.flags &= ~(flags | (__TIF_NEED_STOP | __TIF_NEED_FREEZE));
	smp_wmb();

	if (flags & __TIF_NEED_STOP)
		task->state = TASK_STATE_STOP;
	else if (flags & __TIF_NEED_FREEZE)
		task->state = TASK_STATE_SUSPEND;

	if (task->state != TASK_STATE_RUNNING) {
		sched();
		panic("%s %d: should not be here\n", __func__, __LINE__);
	}

	if (task->return_to_user)
		task->return_to_user(task, regs);
}

// 释放 task
void do_release_task(struct task *task)
{
	// 释放 task，目前是空函数？？？
	arch_release_task(task);
	//释放栈空间
	free_pages(task->stack_bottom);
	// 释放 task 结构体
	free(task);

	/*
	 * this function can not be called at interrupt
	 * context, use release_task is more safe
	 */
	// 释放该 tid
	release_tid(task->tid);
}

// 创建 task
struct task *__create_task(char *name,
			task_func_t func,
			uint32_t stk_size,
			int prio,
			int aff,
			unsigned long opt,
			void *arg)
{
	struct task *task;
	int tid;

	// 设置该 task 的 CPU 亲和性
	if ((aff >= NR_CPUS) && (aff != TASK_AFF_ANY)) {
		pr_warn("task %s afinity will set to 0x%x\n",
				name, TASK_AFF_ANY);
		aff = TASK_AFF_ANY;
	}

	// 设置该 task 的 优先级
	if ((prio >= OS_PRIO_IDLE) || (prio < 0)) {
		pr_warn("wrong task prio %d fallback to %d\n",
				prio, OS_PRIO_DEFAULT_6);
		prio = OS_PRIO_DEFAULT_6;
	}

	// 分配 tid
	tid = alloc_tid();
	if (tid < 0)
		return NULL;
	
	// 当前 task 不可被抢占
	preempt_disable();

	// 创建一个 task 结构体，初始化 task 结构体
	task = do_create_task(name, func, stk_size, prio,
			tid, aff, opt, arg);
	if (!task) {
		release_tid(tid);
		preempt_enable();
		return NULL;
	}

	// 目前没做什么实际的事情
	task_create_hook(task);

	/*
	 * vcpu task will have it own arch_init_task function which
	 * is called arch_init_vcpu()
	 */
	// 如果不是 vcpu 类型的 task
	if (!(task->flags & TASK_FLAGS_VCPU))
		arch_init_task(task, (void *)func, 0, task->pdata);

	/*
	 * start the task if need auto started.
	 */
	// 如果没有设置自动开始，vcpu task 具有该标志
	if (!(task->flags & TASK_FLAGS_NO_AUTO_START))
		// 将该 task 加入到某个 pcpu 的 read_list
		task_ready(task, 0);

	// 允许该 task 抢占了
	preempt_enable();

	if (os_is_running())
		//调度
		sched();

	return task;
}

struct task *create_task(char *name,
		task_func_t func,
		size_t stk_size,
		int prio,
		int aff,
		unsigned long opt,
		void *arg)
{
	// 数字越小，优先级越高
	if (prio < 0) {
		if (opt & OS_PRIO_VCPU)
			prio = OS_PRIO_VCPU;
		else
			prio = OS_PRIO_DEFAULT;
	}

	return __create_task(name, func, stk_size, prio, aff, opt, arg);
}

// 为当前的 pcpu 创建 idle task
int create_idle_task(void)
{
	struct task *task;
	char task_name[32];
	int aff = smp_processor_id();
	int tid = OS_NR_TASKS - 1 - aff;
	struct pcpu *pcpu = get_pcpu();

	task = get_cpu_var(idle_task);  //获取当前cpu对应的idle_task结构体指针
	BUG_ON(!request_tid(tid), "tid is wrong for idle task cpu%d\n", tid);

	sprintf(task_name, "idle/%d", aff);

	// 初始化该 idle_task
	task_init(task, task_name, NULL, 0, OS_PRIO_IDLE,
			tid, aff, TASK_FLAGS_IDLE, NULL);

	// 汇编中 boot.S 已经将 idle_stack 设置好了
	task->stack_top = (void *)ptov(minos_stack_top) -
		(aff << CONFIG_TASK_STACK_SHIFT);
	task->stack_bottom = task->stack_top - CONFIG_TASK_STACK_SIZE;

	task->state = TASK_STATE_RUNNING;
	task->cpu = aff;
	task->run_time = 0;

	pcpu->running_task = task;
	// 设置当前 task 为该 task，也就是设置 x18 寄存器
	set_current_task(task);

	/* call the hooks for the idle task */
	// create task 时的 hook 函数，目前没有
	task_create_hook(task);

	// 将该 task 加入到 pcpu 的 ready_list
	list_add_tail(&pcpu->ready_list[task->prio], &task->state_list);
	pcpu->local_rdy_grp |= BIT(task->prio);
	pcpu->idle_task = task;

	return 0;
}

// 对OS所有的task做某个操作
void os_for_all_task(void (*hdl)(struct task *task))
{
        struct task *task;
	int idx;

	// get the tid_lock ?
	for_each_set_bit(idx, tid_map, OS_NR_TASKS) {
		task = os_task_table[idx];
		if (!task)
			continue;
		hdl(task);
	}
}

/*
 * for preempt_disable and preempt_enable need
 * to set the current task at boot stage
 */
static int __init_text task_early_init(void)
{
	struct task *task;
	int i = smp_processor_id();

	task = &idle_tasks[i];
	memset(task, 0, sizeof(struct task));
	get_per_cpu(idle_task, i) = task;

	/* init the task info for the thread */
	TASK_INFO_INIT(current_task_info, task);

	return 0;
}
early_initcall_percpu(task_early_init);

// 创建 per cpu 类型的 task
int create_percpu_tasks(char *name, task_func_t func, 
		int prio, unsigned long flags, void *pdata)
{
	struct task *ret;
	int cpu;

	// 遍历每个在线的 cpu
	for_each_online_cpu(cpu) {
		ret = create_task(name, func, TASK_STACK_SIZE, prio, cpu,
				flags | TASK_FLAGS_PERCPU, pdata);
		if (ret == NULL)
			pr_err("create [%s] fail on cpu%d\n", name, cpu);
	}

	return 0;
}

struct task *create_vcpu_task(char *name, task_func_t func, int aff,
		unsigned long flags, void *vcpu)
{
#define VCPU_TASK_FLAG (TASK_FLAGS_VCPU | TASK_FLAGS_NO_AUTO_START)
        return create_task(name, func, TASK_STACK_SIZE, OS_PRIO_VCPU, aff,
			flags | VCPU_TASK_FLAG, vcpu);
}
