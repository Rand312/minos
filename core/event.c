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
#include <minos/task.h>
#include <minos/sched.h>
#include <minos/event.h>
#include <minos/mm.h>
#include <minos/smp.h>

// 初始化事件结构体
void event_init(struct event *event, int type, void *pdata)
{
	event->type = type;
	spin_lock_init(&event->lock);
	init_list(&event->wait_list);
	event->data = pdata;

	if (event->type == OS_EVENT_TYPE_NORMAL) {
		if (pdata == NULL)
			event->data = (void *)current;
		event->owner = current->tid;
		event->cnt = 0;
	}
}

// 等待事件，没有休眠之类的？？？？
void __wait_event(void *ev, int mode, uint32_t to)
{
	struct task *task = current;
	struct event *event;

	/*
	 * the process of flag is different with other IPC
	 * method
	 */
	if (mode == OS_EVENT_TYPE_FLAG) {
		task->flag_node = ev;
	} else {
		event = (struct event *)ev;
		list_add_tail(&event->wait_list, &task->event_list);
	}

	/*
	 * after event_task_wait, the process will call sched()
	 * by itself, before sched() is called, the task can not
	 * be sched out, since at the same time another thread
	 * may wake up this process, which may case dead lock
	 * with current design.
	 */
	//设置任务状态
	do_not_preempt();
	task->state = TASK_STATE_WAIT_EVENT;
	task->pend_state = TASK_STATE_PEND_OK;
	task->wait_type = mode;
	task->delay = (to == -1 ? 0 : to);
}

// 从链表中移除 event 
int remove_event_waiter(struct event *ev, struct task *task)
{
	if (task->event_list.next == NULL) {
		return -ENOENT;
	} else {
		list_del(&task->event_list);
		task->event_list.next = NULL;

		return 0;
	}
}

// 从链表中获取一个 event
static inline struct task *get_event_waiter(struct event *ev)
{
	struct task *task;

	if (is_list_empty(&ev->wait_list))
		return NULL;

	task = list_first_entry(&ev->wait_list, struct task, event_list);
	list_del(&task->event_list);

	return task;
}

/*
 * num - the number need to wake ? <= 0 means, wakeup all.
 * will return the number of task which have been wake.
 */
// 获取一个 event，然后执行唤醒操作
int __wake_up_event_waiter(struct event *ev, void *msg,
		int pend_state, int opt)
{
	struct task *task;
	int ret, cnt = 0, num;

	num = opt & OS_EVENT_OPT_BROADCAST ? 0 : 1;

	do {
		task = get_event_waiter(ev);
		if (!task)
			break;

		ret = __wake_up(task, pend_state, ev->type, msg);
		if (ret)
			continue;

		if (++cnt == num)
			break;
	} while (1);

	return cnt;
}

// 设置当前 task 的 pend_state 为 TASK_STATE_PEND_OK
void event_pend_down(void)
{
	struct task *task = current;

	task->pend_state = TASK_STATE_PEND_OK;
	task->wait_event = (unsigned long)NULL;
	task->wait_type = 0;
	task->msg = NULL;
}

long wake(struct event *ev)
{
	struct task *task = (struct task *)ev->data;
	unsigned long flags;
	int ret;

	if (ev->type != OS_EVENT_TYPE_NORMAL) {
		pr_err("event type %d can not use wake\n");
		return -EPERM;
	}

	if (task == current) {
		return __wake_up(task, TASK_STATE_PEND_OK,
				OS_EVENT_TYPE_NORMAL, NULL);
	} else {
		spin_lock_irqsave(&ev->lock, flags);
		ret = __wake_up(task, TASK_STATE_PEND_OK,
					OS_EVENT_TYPE_NORMAL, NULL);
		spin_unlock_irqrestore(&ev->lock, flags);
	}

	return ret;
}
