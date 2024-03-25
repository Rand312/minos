#ifndef __TASK_DEF_H__
#define __TASK_DEF_H__

#include <minos/types.h>
#include <minos/task_info.h>
#include <minos/list.h>
#include <minos/atomic.h>
#include <minos/timer.h>
#include <asm/tcb.h>

#ifdef CONFIG_TASK_STACK_SIZE
#define TASK_STACK_SIZE	CONFIG_TASK_STACK_SIZE
#else
#define TASK_STACK_SIZE (2 * PAGE_SIZE)
#endif

#ifndef CONFIG_NR_TASKS
#define CONFIG_NR_TASKS 256
#endif

#define OS_NR_TASKS CONFIG_NR_TASKS

#define OS_PRIO_MAX		8
#define OS_PRIO_DEFAULT_0	0
#define OS_PRIO_DEFAULT_1	1
#define OS_PRIO_DEFAULT_2	2
#define OS_PRIO_DEFAULT_3	3
#define OS_PRIO_DEFAULT_4	4
#define OS_PRIO_DEFAULT_5	5
#define OS_PRIO_DEFAULT_6	6
#define OS_PRIO_DEFAULT_7	7

#define OS_PRIO_REALTIME	OS_PRIO_DEFAULT_0
#define OS_PRIO_SYSTEM		OS_PRIO_DEFAULT_3
#define OS_PRIO_VCPU		OS_PRIO_DEFAULT_4
#define OS_PRIO_DEFAULT		OS_PRIO_DEFAULT_5
#define OS_PRIO_IDLE		OS_PRIO_DEFAULT_7
#define OS_PRIO_LOWEST		OS_PRIO_IDLE

#define TASK_FLAGS_VCPU			BIT(0)
#define TASK_FLAGS_REALTIME		BIT(1)
#define TASK_FLAGS_IDLE			BIT(2)
#define TASK_FLAGS_NO_AUTO_START	BIT(3)
#define TASK_FLAGS_32BIT		BIT(4)
#define TASK_FLAGS_PERCPU		BIT(5)

#define TASK_AFF_ANY		(-1)
#define TASK_NAME_SIZE		(32)

#define TASK_STATE_RUNNING 0x00
#define TASK_STATE_READY 0x01
#define TASK_STATE_WAIT_EVENT 0x02
#define TASK_STATE_WAKING 0x04
#define TASK_STATE_SUSPEND 0x08
#define TASK_STATE_STOP 0x10

#define KWORKER_FLAG_MASK 0xffff
#define KWORKER_TASK_RECYCLE BIT(0)

#define TASK_STATE_PEND_OK       0u  /* Pending status OK, not pending, or pending complete */
#define TASK_STATE_PEND_TO       1u  /* Pending timed out */
#define TASK_STATE_PEND_ABORT    2u  /* Pending aborted */

#define KWORKER_FLAG_MASK	0xffff
#define KWORKER_TASK_RECYCLE	BIT(0)

#define TASK_TIMEOUT_CLEAR	0x0
#define TASK_TIMEOUT_REQUESTED	0x1
#define TASK_TIMEOUT_TRIGGER	0x2

#define TASK_REQ_FLUSH_TLB	(1 << 0)
#define TASK_REQ_STOP		(1 << 1)

typedef int (*task_func_t)(void *data);

struct process;

#ifdef CONFIG_VIRT
struct vcpu;
#endif

struct task {
	// task_info，类似 Linux 中的 thread_info
	struct task_info ti;
	// 内核栈指针
	void *stack_base;
	void *stack_top;
	void *stack_bottom;
	// 线程 id
	int tid;

	// 线程类型
	// #define TASK_FLAGS_VCPU			BIT(0)
	// #define TASK_FLAGS_REALTIME		BIT(1)
	// #define TASK_FLAGS_IDLE			BIT(2)
	// #define TASK_FLAGS_NO_AUTO_START	BIT(3)
	// #define TASK_FLAGS_32BIT			BIT(4)
	// #define TASK_FLAGS_PERCPU		BIT(5)
	unsigned long flags;

	// 该线程的一些链接节点
	struct list_head task_list;	// link to the task list, if is a thread.
	struct list_head state_list;	// link to the sched list used for sched.

	// 延时 timer
	uint32_t delay;
	struct timer delay_timer;

	/*
	 * the spinlock will use to protect the below member
	 * which may modified by different cpu at the same
	 * time:
	 * 1 - state
	 * 2 - pend_state
	 */
	// 该线程的自旋锁，用来保护下面的一些结构
	spinlock_t s_lock;
	int state;
	long pend_state;
	long request;
	// 线程等待需要用到的一些结构
	int wait_type;			// which event is task waitting for.
	void *msg;			// used for mbox to pass data
	unsigned long wait_event;	// the event instance which the task is waitting.
	struct list_head event_list;

	struct flag_node *flag_node;	// used for the flag event.
	long flags_rdy;

	/*
	 * affinity - the cpu node which the task affinity to
	 */
	// 线程亲和性相关
	int cpu;        // 线程现在正运行在哪个 cpu
	int last_cpu;   // 线程上一次运行在哪个 cpu
	int affinity;   // 线程可以运行在哪些 cpu 上
	int prio;       // 该线程的优先级

	unsigned long run_time;  // 该线程已经执行的时间

	unsigned long ctx_sw_cnt;	// switch count of this task. 上下文切换次数
	unsigned long start_ns;		// when the task started last time. 

	// 该线程的名字
	char name[TASK_NAME_SIZE];

	// vcpu 线程需要执行的函数，退出和进入 guest 将要调用的函数
	void (*exit_from_user)(struct task *task, gp_regs *regs);
	void (*return_to_user)(struct task *task, gp_regs *regs);

	// 该线程的私有数据
	union {
		void *pdata;			// the private data of this task, such as vcpu.
#ifdef CONFIG_VIRT
		struct vcpu *vcpu;
#endif
	};

	// 该线程的上下文保存地方
	struct cpu_context cpu_context;
} __cache_line_align;

#define OS_TASK_RESERVED	((struct task *)1)

#endif
