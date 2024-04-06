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
#include <minos/task.h>
#include <minos/sched.h>
#include <minos/irq.h>
#include <minos/softirq.h>
#include <minos/of.h>
#include <minos/bootarg.h>
#include <minos/mm.h>
#include <minos/flag.h>

#ifdef CONFIG_VIRT
#include <virt/virt.h>
#include <virt/vm.h>
#endif

DEFINE_PER_CPU(struct pcpu *, pcpu);

extern struct task *os_task_table[OS_NR_TASKS];

// 检查当前是否允许调度，处于中断、不可抢占状态都不能调度
#define sched_check()								\
	do {									\
		if (in_interrupt() || (irq_disabled() && !preempt_allowed()))	\
			panic("sched is disabled %s %d\n", __func__, __LINE__);	\
	} while (0)

void __might_sleep(const char *file, int line, int preempt_offset)
{
	struct task *task = current;

	WARN_ONCE(task->state != TASK_STATE_RUNNING,
			"do not call blocking ops when !TASK_RUNNING; "
			"state=%d", task->state);

	if (preempt_allowed() && !irq_disabled() && !task_is_idle(task))
		return;

	pr_err("BUG: sleeping function called from invalid context at %d %s:%d\n",
			current->ti.preempt_count, file, line);
	dump_stack(NULL, (unsigned long *)arch_get_sp());
}

static inline void sched_update_sched_timer(void)
{
	struct pcpu *pcpu = get_pcpu();
	struct task *task = current;

	/*
	 * enable the sched timer if there are more than one
	 * ready task on the same prio.
	 */
	// 当前优先级队列的 task 数量超过 1 个，那么需要调度了，开始 pcpu 的 sched_timer
	// task->run_time 为当前 task 的时间片
	if ((pcpu->tasks_in_prio[task->prio] > 1))
		setup_and_start_timer(&pcpu->sched_timer, MILLISECS(task->run_time));
	// 当前优先级队列 上只有 1 个或者没有 task 的时候，不需要调度，也就不需要 sched_timer，所以停止 timer
	else
		stop_timer(&pcpu->sched_timer);
}

// 将 task 添加到 ready_list
static void add_task_to_ready_list(struct pcpu *pcpu,
		struct task *task, int preempt)
{
	/*
	 * make sure the new task is insert to front of the current
	 * task.
	 *
	 * if the prio is equal to the current task's prio, insert to
	 * the front of the current task.
	 */
	ASSERT(task->state_list.next == NULL);
	pcpu->tasks_in_prio[task->prio]++;
	// 如果当前 task 的优先级 == 将要添加的 task 的优先级
	if (current->prio == task->prio) {
		// 直接插入到当前 task 的前面，方便抢占执行
		list_insert_before(&current->state_list, &task->state_list);
		//如果该优先级的task刚好只有它们两个，更新 pcpu sched_timer
		if (pcpu->tasks_in_prio[task->prio] == 2)
			sched_update_sched_timer();
	} else {
		//否则直接将该 task 添加到相应优先级队列的末尾
		list_add_tail(&pcpu->ready_list[task->prio], &task->state_list);
	}

	mb();
	// 该优先级队列上有 task 了，那么该优先级队列对应的位图上置 1
	pcpu->local_rdy_grp |= BIT(task->prio);
	// 如果允许抢占了，并且新 task 的优先级比较高，设置抢占标志，抢占时机为异常返回
	if (preempt || current->prio > task->prio)
		set_need_resched();
}

// 移除 pcpu 上的 task
static void remove_task_from_ready_list(struct pcpu *pcpu, struct task *task)
{
	ASSERT(task->state_list.next != NULL);

	// 从 &pcpu->ready_list[task->prio] 链表中删除该 task
	list_del(&task->state_list);
	// 如果该task对应的优先级链表空了
	if (is_list_empty(&pcpu->ready_list[task->prio]))
		//将相应的位图清零
		pcpu->local_rdy_grp &= ~BIT(task->prio);
	mb();

	//相应优先级 task 数量 --
	pcpu->tasks_in_prio[task->prio]--;

	/*
	 * check whether need to stop the sched timer.
	 */
	//如果移除的task优先级与当前task优先级相同，且移除后只剩下当前 task，更新该 pcpu 的 sched_timer，这里其实就是 stop sched timer
	if ((current->prio == task->prio) &&
			(pcpu->tasks_in_prio[task->prio] == 1))
		sched_update_sched_timer();
}

// 发送 SGI 类型中断
void pcpu_resched(int pcpu_id)
{
	send_sgi(CONFIG_MINOS_RESCHED_IRQ, pcpu_id);
}

// 发送 CONFIG_MINOS_IRQWORK_IRQ 类型的 SGI 给目标 pcpu，让其加入一个 task
void pcpu_irqwork(int pcpu_id)
{
	send_sgi(CONFIG_MINOS_IRQWORK_IRQ, pcpu_id);
}

static int select_task_run_cpu(void)
{
	/*
	 * TBD to be determined 待确认
	 */
	return (NR_CPUS - 1);
}

// 将 task 添加到 pcpu 的 read_list
static void percpu_task_ready(struct pcpu *pcpu, struct task *task, int preempt)
{
	unsigned long flags;
	// 关中断
	// MARK，为什么要关中断
	local_irq_save(flags);
	add_task_to_ready_list(pcpu, task, preempt);
	local_irq_restore(flags);
}

// 将该 task 加入到 pcpu 的 new_list
static inline void smp_percpu_task_ready(struct pcpu *pcpu,
		struct task *task, int preempt)
{
	unsigned long flags;
	// 如果想让这个新的 task 抢占现有的进程，设置 resched 标志
	if (preempt)
		task_set_resched(task);

	ASSERT(task->state_list.next == NULL);
	spin_lock_irqsave(&pcpu->lock, flags);
	// 将新 task 加入目标 pcpu 的 new_list 队列中
	// 优先级队列是调度队列，当前 pcpu 没权利直接修改别的 pcpu 的调度队列
	list_add_tail(&pcpu->new_list, &task->state_list);
	spin_unlock_irqrestore(&pcpu->lock, flags);

	pcpu_irqwork(pcpu->pcpu_id);
}

// 将 task 添加到某个 pcpu 的 ready_list 上面
int task_ready(struct task *task, int preempt)
{
	struct pcpu *pcpu, *tpcpu;
	// 关抢占
	preempt_disable();
	// 根据亲和性设置 cpuid，亲和性是调用 create_task 是作为参数传进去的
	// 目前系统代码中调用 create_task 时，只有 当前pcpu_id，和 -1 两种情况
	// 所以这里的 task->cpu 要么等于当前的 pcpu id
	task->cpu = task->affinity;
	// 要么设置为 NR_CPUS - 1(id 值最大的那个 pcpu)
	if (task->cpu == -1)
		task->cpu = select_task_run_cpu();

	/*
	 * if the task is a precpu task and the cpu is not
	 * the cpu which this task affinity to then put this
	 * cpu to the new_list of the pcpu and send a resched
	 * interrupt to the pcpu
	 */

	pcpu = get_pcpu();
	// 如果当前的 pcpu 与 task 亲和的 cpu 不一致
	if (pcpu->pcpu_id != task->cpu) {
		// 获取该 task 对应的 pcpu
		tpcpu = get_per_cpu(pcpu, task->cpu);
		smp_percpu_task_ready(tpcpu, task, preempt);
	// 将新 task 添加到当前 pcpu 的 ready list 上
	} else {
		percpu_task_ready(pcpu, task, preempt);
	}

	preempt_enable();

	return 0;
}

// 设置状态为 TASK_STATE_WAIT_EVENT，记录睡眠时间 delay 到 task->delay
// 最后在调用 sched 调度
void task_sleep(uint32_t delay)
{
	struct task *task = current;
	unsigned long flags;

	/*
	 * task sleep will wait for the sleep timer expired
	 * or the event happend
	 */
	local_irq_save(flags);
	do_not_preempt();
	task->delay = delay;
	task->state = TASK_STATE_WAIT_EVENT;
	task->wait_type = OS_EVENT_TYPE_TIMER;
	local_irq_restore(flags);

	sched();
}

// 设置 task 的状态为 TASK_STATE_SUSPEND，然后调度
void task_suspend(void)
{
	struct task *task = current;
	unsigned long flags;

	local_irq_save(flags);
	do_not_preempt();
	task->delay = 0;
	task->state = TASK_STATE_SUSPEND;
	task->wait_type = 0;
	local_irq_restore(flags);

	sched();
}

// 挑选下一个在 pcpu 上执行的任务
static struct task *pick_next_task(struct pcpu *pcpu)
{
	struct list_head *head;
	struct task *task = current;
	int prio;

	/*
	 * if the current task need to sleep or waitting some
	 * event happen. delete it from the ready list, then the
	 * next run task can be got.
	 */
	mb();
	ASSERT(task->state != TASK_STATE_READY);

	// 处理当前 task
	// 如果当前的 task 不是 RUNNING 状态
	if (!task_is_running(task)) {
		// 从 ready_list 中删除
		remove_task_from_ready_list(pcpu, task);
				// 如果当前状态是 STOP，将该 task 添加到 stop_list
                if (task->state == TASK_STATE_STOP) {
                        list_add_tail(&pcpu->stop_list, &task->state_list);
			flag_set(&pcpu->kworker_flag, KWORKER_TASK_RECYCLE);
		}
	}

	/*
	 * get the highest ready task list to running
	 */
	// 获取最高优先级 
	prio = ffs_one_table[pcpu->local_rdy_grp];
	ASSERT(prio != -1);
	// 获取最高优先级链表头
	head = &pcpu->ready_list[prio];

	/*
	 * get the first task, then put the next running
	 * task to the end of the ready list.
	 */
	ASSERT(!is_list_empty(head));
	// 获取该优先级链表的第一个节点
	task = list_first_entry(head, struct task, state_list);
	// 从 ready_list 链表中删除
	list_del(&task->state_list);
	// 然后添加到 ready_list 的末尾
	list_add_tail(head, &task->state_list);

	return task;
}

// 切换 task
static void switch_to_task(struct task *cur, struct task *next)
{	
	// 获取当前的 pcpu
	struct pcpu *pcpu = get_pcpu();
	unsigned long now;

	// 保存 cur task 的上下文到 task->cpu_context.fpsimd_state
	arch_task_sched_out(cur);
	// call OS_HOOK_TASK_SWITCH_OUT 类型的 hook 函数
	do_hooks((void *)cur, NULL, OS_HOOK_TASK_SWITCH_OUT);

	// 获取当前时间 
	now = NOW();

	/* 
	 * check the current task's state and do some action
	 * to it, check whether it suspend time is set or not
	 *
	 * if the task is ready state, adjust the run time of
	 * this task. If the task need to wait some event, and
	 * need request a timeout timer then need setup the timer.
	 */

	// 如果该 task 状态为 TASK_STATE_WAIT_EVENT，并且设置了 delay，那么开始计时 delay_timer
	if ((cur->state == TASK_STATE_WAIT_EVENT) && (cur->delay > 0))
		setup_and_start_timer(&cur->delay_timer,
				MILLISECS(cur->delay));
	// 否则如果当前 task 为 RUNNING 状态，那么切换到 READY 状态
	else if (cur->state == TASK_STATE_RUNNING)
		cur->state = TASK_STATE_READY;
	
	// 记录当前 task 上个 CPU 为当前 CPU，重新设置 task 的时间片
	cur->last_cpu = cur->cpu;
	cur->run_time = CONFIG_TASK_RUN_TIME;
	smp_wmb();

	/*
	 * notify the cpu which need to waku-up this task that
	 * the task has been do to sched out, can be wakeed up
	 * safe, the task is offline now.
	 */
	cur->cpu = -1;
	smp_wmb();

	/*
	 * change the current task to next task.
	 */
	// next task 的状态设置为 TASK_STATE_RUNNING
	// 清除掉 __TIF_TICK_EXHAUST 标志，表示时间片到期的标志
	next->state = TASK_STATE_RUNNING;
	next->ti.flags &= ~__TIF_TICK_EXHAUST;
	// next task 的 cpu 设置为当前 pcpu 的 id
	next->cpu = pcpu->pcpu_id;
	// 设置“当前” task 为 next task
	set_current_task(next);
	pcpu->running_task = next;

	//恢复 next task 的上下文
	arch_task_sched_in(next);
	//call 类型为 OS_HOOK_TASK_SWITCH_TO hook 函数
	do_hooks((void *)next, NULL, OS_HOOK_TASK_SWITCH_TO);

	next->ctx_sw_cnt++;  // next task 的调度次数++
	next->wait_event = 0;  
	// 设置开始时间
	next->start_ns = now;
	smp_wmb();
}

// 时间片到了，need resched
static void sched_tick_handler(unsigned long data)
{
	struct task *task = current;

	/*
	 * mark this task has used its running ticket, and the sched
	 * timer is off.
	 */
	// 标志着该 task 的时间片用完了
	task->ti.flags |= __TIF_TICK_EXHAUST;
	// 需要重新调度，设置 __TIF_NEED_RESCHED 标志
	set_need_resched();
}

// sched 系统调用，只是一条 svc #0 指令
static void inline sys_sched(void)
{
	sched_check();
	arch_sys_sched();
}

// 调用 sys_sched
void sched(void)
{
	/*
	 * tell the scheduler that I am ok to sched out.
	 */
	set_need_resched();
	clear_do_not_preempt();

	do {
		sys_sched();
	// 如果需要调度，则 while 循环
	// MARK，什么时候会出现中途不再需要调度
	} while (need_resched());
}

// 允许抢占 && 处于开中断状态，那么允许调度
static inline int sched_allowed(void)
{
	return preempt_allowed() && !irq_disabled();
}

// 条件 resched，也就是说允许调度 && 需要调度的时候才调度
void cond_resched(void)
{
	if (need_resched() && sched_allowed())
		sched();
}

// 进入 hardirq 上下文
void irq_enter(gp_regs *regs)
{
	current_task_info->flags |= __TIF_HARDIRQ_MASK;
	wmb();
}

// 退出 hardirq 上下文
void irq_exit(gp_regs *regs)
{
	current_task_info->flags &= ~__TIF_HARDIRQ_MASK;
	wmb();
}

// 任务退出，设置当前任务状态为 STOP，然后 sched
void task_exit(int errno)
{
	set_current_state(TASK_STATE_STOP, 0);
	sched();
}

// 在异常返回的时候做 resched 操作
static inline int __exception_return_handler(void)
{
	struct task *next, *task = current;
	struct task_info *ti = to_task_info(task);
	struct pcpu *pcpu = get_pcpu();

	/*
	 * if the task is suspend state, means next the cpu
	 * will call sched directly, so do not sched out here
	 *
	 * 1 - when preempt_count > 0, the scheduler whill try
	 *     to shced() when preempt_enable.
	 * 2 - __TIF_DONOT_PREEMPT is set, it will call sched() at
	 *    once.
	 */
	// 如果不需要 resched 或者 不允许抢占 或者 不要抢占，那么再次执行该 task
	if (!(ti->flags & __TIF_NEED_RESCHED) || (ti->preempt_count > 0) ||
			(ti->flags & __TIF_DONOT_PREEMPT))
		// 那么就再 run 一下
		goto task_run_again;

	// 否则先清除 __TIF_NEED_RESCHED（因为马上就要 resched，所以不需要该标志了）
	ti->flags &= ~__TIF_NEED_RESCHED;

	// 然后挑选 next task
	next = pick_next_task(pcpu);
	// 如果挑选的就是当前 task
	if ((next == task))
		goto task_run_again;
	
	// 切换 task
	switch_to_task(task, next);

	return 0;

task_run_again:
	// 清除掉当前 task 时间片已经到了的标志 TIF_TICK_EXHAUST
	if (test_and_clear_bit(TIF_TICK_EXHAUST, &ti->flags))
		return -EAGAIN;
	else
		return -EACCES;
}

// 异常返回时，检查是否需要 resched
void exception_return_handler(void)
{
	int ret = __exception_return_handler();

	// 只要不是执行出错，那么这里都会重新开始执行一个 task，所以这里重启 sched_timer
	if ((ret == 0) || (ret == -EAGAIN))
		sched_update_sched_timer();
}

// 将一个 task 添加到非当前 pcpu 时会触发 irqwork_handler
static int irqwork_handler(uint32_t irq, void *data)
{
	struct pcpu *pcpu = get_pcpu();
	struct task *task, *n;
	int preempt = 0, need_preempt;

	/*
	 * check whether there are new taskes need to
	 * set to ready state again
	 */
	raw_spin_lock(&pcpu->lock);
	// 遍历 pcpu->new_list 上面的每一个 task
	// 
	list_for_each_entry_safe(task, n, &pcpu->new_list, state_list) {
		/*
		 * remove it from the new_next.
		 */
		// 从 new_list 中删除
		list_del(&task->state_list);

		// 位于 new_list 上的 task 不应该为 TASK_STATE_RUNNING 状态
		if (task->state == TASK_STATE_RUNNING) {
			pr_err("task %s state %d wrong\n",
				task->name? task->name : "Null", task->state);
			continue;
		}

		// 计算需要 resched 的 task 数量
		// 猜测含义：该 task 优先级较高，将它挂入 ready list 后，我们向 resched 来执行它
		need_preempt = task_need_resched(task);
		preempt += need_preempt;
		// 清除掉该 task 的 resched 标志
		task_clear_resched(task);

		// 将该 task 添加到当前 pcpu 的 ready_list
		add_task_to_ready_list(pcpu, task, need_preempt);
		task->state = TASK_STATE_READY;

		/*
		 * if the task has delay timer, cancel it.
		 */
		// 如果该 task 有 delay_timer，直接取消
		// MARK，为什么这么做，情景是什么
		if (task->delay) {
			stop_timer(&task->delay_timer);
			task->delay = 0;
		}
	}
	raw_spin_unlock(&pcpu->lock);
	// 如果允许抢占，或者当前 task 是 idle task，设置 resched 标志，在异常返回的时候 sched
	if (preempt || task_is_idle(current))
		set_need_resched();

	return 0;
}

static int resched_handler(uint32_t irq, void *data)
{
	set_need_resched();
	return 0;
}

int local_sched_init(void)
{
	struct pcpu *pcpu = get_pcpu();

	// 初始化 pcpu 的 pcpu 的 sched_timer，设置相应的 handler
	init_timer(&pcpu->sched_timer, sched_tick_handler, (unsigned long)pcpu);

	pcpu->state = PCPU_STATE_RUNNING;

	// 注册两种中断
	request_irq(CONFIG_MINOS_RESCHED_IRQ, resched_handler,
			0, "resched handler", NULL);
	request_irq(CONFIG_MINOS_IRQWORK_IRQ, irqwork_handler,
			0, "irqwork handler", NULL);
	return 0;
}

// 初始化 pcpu 的各类 list
static void pcpu_sched_init(struct pcpu *pcpu)
{
	init_list(&pcpu->new_list);
	init_list(&pcpu->stop_list);
	init_list(&pcpu->ready_list[0]);
	init_list(&pcpu->ready_list[1]);
	init_list(&pcpu->ready_list[2]);
	init_list(&pcpu->ready_list[3]);
	init_list(&pcpu->ready_list[4]);
	init_list(&pcpu->ready_list[5]);
	init_list(&pcpu->ready_list[6]);
	init_list(&pcpu->ready_list[7]);
}

int sched_init(void)
{
	int i;

	for (i = 0; i < NR_CPUS; i++)
		pcpu_sched_init(&pcpus[i]);

	return 0;
}

static int wake_up_interrupted(struct task *task,
		long pend_state, int event, void *data)
{
	unsigned long flags;

	ASSERT(pend_state != TASK_STATE_PEND_TO);
	if (task->state != TASK_STATE_WAIT_EVENT)
		return -EACCES;

	if (!irq_disabled())
		panic("unexpected irq happend when wait_event() ?\n");

	/*
	 * the interrup occurs when task try to wait_event. in
	 * addition:
	 * 1 - the interrupt is happended in the same cpu.
	 * 2 - will not the delay timer, since the delay time
	 *     has not been set already.
	 * 3 - the state must TASK_STATE_WAIT_EVENT
	 * 4 - task has not been in sched routine.
	 *
	 * meanwhile, other cpu may already in the wake up function
	 * try to wake up the task, then need check this suitation
	 * since other cpu while check cpu == -1, this will lead
	 * to dead lock if use spin_lock function. So here use
	 * spin_trylock instead.
	 */
	if (!spin_trylock_irqsave(&task->s_lock, flags))
		return -EBUSY;

	if (task->state != TASK_STATE_WAIT_EVENT) {
		spin_unlock_irqrestore(&task->s_lock, flags);
		return -EINVAL;
	}

	task->ti.flags |= __TIF_WAIT_INTERRUPTED;
	task->ti.flags &= ~__TIF_DONOT_PREEMPT;

	/*
	 * here this cpu got this task, and can set the new
	 * state to running and run it again.
	 */
	task->pend_state = pend_state;
	task->state = TASK_STATE_RUNNING;
	task->delay = 0;
	if (event == OS_EVENT_TYPE_FLAG) {
		task->flags_rdy = (long)data;
		task->msg = NULL;
	} else {
		task->msg = data;
		task->flags_rdy = 0;
	}
	spin_unlock_irqrestore(&task->s_lock, flags);

	return 0;
}

static int wake_up_common(struct task *task, long pend_state, int event, void *data)
{
	unsigned long flags;
	uint32_t timeout;

	preempt_disable();
	spin_lock_irqsave(&task->s_lock, flags);

	/*
	 * task already waked up, if the stat is set to
	 * TASK_STATE_WAIT_EVENT, it means that the task will
	 * call sched() to sleep or wait something happen.
	 */
	if (task->state != TASK_STATE_WAIT_EVENT) {
		spin_unlock_irqrestore(&task->s_lock, flags);
		preempt_enable();
		return -EPERM;
	}

	/*
	 * the task may in sched() routine on other cpu
	 * wait the task really out of running. since the task
	 * will not preempt in the kernel space now, so the cpu
	 * of the task will change to -1 at one time.
	 *
	 * since the kernel can not be preempted so it can make
	 * sure that sched() can be finish its work.
	 */
	while (task->cpu != -1)
		cpu_relax();

	/*
	 * here this cpu got this task, and can set the new
	 * state to running and run it again.
	 */
	task->pend_state = pend_state;
	task->state = TASK_STATE_WAKING;
	timeout = task->delay;
	task->delay = 0;
	if (event == OS_EVENT_TYPE_FLAG) {
		task->flags_rdy = (long)data;
		task->msg = NULL;
	} else {
		task->msg = data;
		task->flags_rdy = 0;
	}

	spin_unlock_irqrestore(&task->s_lock, flags);

	/*
	 * here it means that this task has not been timeout, so can
	 * delete the timer for this task.
	 */
	if (timeout && (task->pend_state != TASK_STATE_PEND_TO))
		stop_timer(&task->delay_timer);

	/*
	 * find a best cpu to run this task.
	 */
	// 将该 task 放入一个
	task_ready(task, 1);
	preempt_enable();

	return 0;
}

int __wake_up(struct task *task, long pend_state, int event, void *data)
{
	if (task == current)
		return wake_up_interrupted(task, pend_state, event, data);
	else
		return wake_up_common(task, pend_state, event, data);
}
