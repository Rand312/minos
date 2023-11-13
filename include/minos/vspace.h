#ifndef __MINOS_VSPACE_H__
#define __MINOS_VSPACE_H__

#include <minos/types.h>
#include <minos/list.h>

// 虚拟地址空间结构体
// 虚拟地址空间其实由页表决定，所以其包含元素为 pgdp
struct vspace {
	pgd_t *pgdp;
	spinlock_t lock;
};

#endif
