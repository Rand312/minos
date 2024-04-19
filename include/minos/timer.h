#ifndef _MINOS_TIMER_H_
#define _MINOS_TIMER_H_

/*
 * refer to linux kernel timer code
 */
#include <minos/time.h>

typedef void (*timer_func_t)(unsigned long);

struct timer {
	int cpu;      // 该 soft timer 挂载哪个 cpu 的 physical timer
	int stop;     // 该 soft timer 是否停止了
	uint64_t expires;    // 该 soft timer 的过期时间，以及是否
	uint64_t timeout;    // delay_timer 使用，expires = now + timeout
	timer_func_t function;   // 该 soft timer 对应的 handler func
	unsigned long data;
	struct list_head entry;
	struct raw_timer *raw_timer;  // 该 soft timer 挂载到哪个物理定时上的
};

/*
 * raw timer is a hardware timer which use to
 * handle timer request.
 */
struct raw_timer {
	struct list_head active;       // 该 timer 是否还活跃状态（其上是否还有软件定时器）
	struct timer *next_timer;      // 下一个软件定时器（其值将会被写入 Compare Value）
	struct timer *running_timer;   // 当前正在运行的软件定时器(其值已经被写入 Compare Value)
	spinlock_t lock;
};

void init_timer(struct timer *timer, timer_func_t fn,
		unsigned long data);

int start_timer(struct timer *timer);
int stop_timer(struct timer *timer);
int read_timer(struct timer *timer);
void setup_timer(struct timer *timer, uint64_t tval);
void setup_and_start_timer(struct timer *timer, uint64_t tval);
int mod_timer(struct timer *timer, uint64_t cval);

#endif
