#ifndef __MINOS_PREEMPT_H__
#define __MINOS_PREEMPT_H__

#include <minos/task_info.h>

extern void cond_resched(void);

// 抢占记数如果为 0 表示允许抢占
// 反之如果不为 0，则表示不允许抢占
static inline int preempt_allowed(void)
{
	return !get_current_task_info()->preempt_count;
}

static inline void preempt_enable(void)
{
	// --，如果为 0 表示允许抢占
	get_current_task_info()->preempt_count--;
	wmb();
	cond_resched();
}

static void inline preempt_disable(void)
{
	get_current_task_info()->preempt_count++;
	wmb();
}

#endif
