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
#include <minos/console.h>
#include <minos/of.h>
#include <minos/spinlock.h>
#include <minos/sched.h>
#include <minos/sem.h>

#define MEM_CONSOLE_SIZE	(2048)
#define CONSOLE_INBUF_SIZE	(2048)

static int widx;
static char mem_log_buf[MEM_CONSOLE_SIZE];

static char console_inbuf[CONSOLE_INBUF_SIZE];
static uint32_t inbuf_ridx, inbuf_widx;

static sem_t console_sem;

#define MEM_CONSOLE_IDX(idx)	(idx & (MEM_CONSOLE_SIZE - 1))
#define BUFIDX(idx)		(idx & (CONSOLE_INBUF_SIZE - 1))


static void mem_console_putc(char ch)
{
	mem_log_buf[MEM_CONSOLE_IDX(widx++)] = ch;
}

static char mem_console_getc(void)
{
	return 0;
}
DEFINE_CONSOLE(mem_console, "mem-console", NULL,
		mem_console_putc, mem_console_getc);

static struct console *console = &__console_mem_console;

// 遍历 console section，获取 name 对应的 console 指针
struct console *get_console(char *name)
{
	extern unsigned long __console_start;
	extern unsigned long __console_end;
	struct console *console;

	if (!name)
		return NULL;

	section_for_each_item(__console_start, __console_end, console) {
		if (strcmp(console->name, name) == 0)
			return console;
	}

	return NULL;
}

// 初始化 控制台
void console_init(char *name)
{
	int index;

	// 初始化此 console 信号量
	sem_init(&console_sem, 0);

	// 根据 name 获取 console 指针
	if (name)
		console = get_console(name);
	// 调用该 console、minos 中就是调用该 串口的初始化函数，比如说 __pl011_init
	if (console->init)
		// __pl011_init((void *)ptov(CONFIG_UART_BASE), 24000000, 115200);
		// CONFIG_UART_BASE=0x9000000
		console->init(NULL);

	/* flush the string in the memory log buf */
	// 输出、flush 当前的 mem_log_buf 中的内容
	for (index = 0; index < MEM_CONSOLE_IDX(widx); index++)
		console->putc(mem_log_buf[index]);
}

void console_putc(char ch)
{
	console->putc(ch);
}

char console_getc(void)
{
	return console->getc();
}

// buf 到 console_inbuf
void console_recv(const char *buf, int cnt)
{
	uint32_t widx;
	int i;

	widx = inbuf_widx;
	rmb();

	for (i = 0; i < cnt; i++)
		console_inbuf[BUFIDX(widx++)] = buf[i];

	wmb();
	inbuf_widx = widx;

	sem_post(&console_sem);
}

void console_puts(char *buf, int len)
{
	puts(buf, len);
}

// console_inbuf 到 buf
int console_gets(char *buf, int max, uint32_t timeout)
{
	uint32_t ridx, widx;
	long i, copy;

	do {
		ridx = inbuf_ridx;
		widx = inbuf_widx;
		rmb();

		ASSERT((widx - ridx) <= CONSOLE_INBUF_SIZE);
		copy = widx - ridx > max ? max : widx - ridx;
		if (copy > 0) {
			for (i = 0; i < copy; i++)
				buf[i] = console_inbuf[BUFIDX(ridx++)];
			wmb();
			inbuf_ridx = ridx;
			break;
		}

		if (timeout > 0)
			copy = sem_pend(&console_sem, timeout);
		else
			break;
	} while (copy == 0);

	return copy;
}
