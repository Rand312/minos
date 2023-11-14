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
#include <asm/arch.h>
#include <device/gicv2.h>
#include <asm/io.h>
#include <minos/cpumask.h>
#include <minos/irq.h>
#include <minos/sched.h>
#include <virt/virq.h>
#include <virt/vdev.h>
#include <virt/resource.h>
#include <virt/virq_chip.h>
#include "vgic.h"
#include <virt/vmodule.h>
#include <minos/of.h>

//GIC-V2 一些特点：
// 最多支持 8 个 CPU

#define VGICV2_MODE_HWA 0x0 // hardware accelerate mode
#define VGICV2_MODE_SWE 0x1 // software emulate mode

static int vgicv2_mode;

// 定义虚拟 gicv2 设备
struct vgicv2_dev {
	struct vdev vdev;
	uint32_t gicd_ctlr;
	uint32_t gicd_typer;
	uint32_t gicd_iidr;
	unsigned long gicd_base;
	unsigned long gicc_base;
	unsigned long gicc_size;
	uint8_t gic_cpu_id[8];
};

// 虚拟 gicv2 的信息
struct vgicv2_info {
	unsigned long gicd_base;
	unsigned long gicd_size;
	unsigned long gicc_base;
	unsigned long gicc_size;
	unsigned long gich_base;
	unsigned long gich_size;
	unsigned long gicv_base;
	unsigned long gicv_size;
};

// virtual gic cpu interface
struct vgicc {
	struct vdev vdev;
	unsigned long gicc_base;
	uint32_t gicc_ctlr;
	uint32_t gicc_pmr;
	uint32_t gicc_bpr;
};

static int gicv2_nr_lrs;
static struct vgicv2_info vgicv2_info;

#define vdev_to_vgicv2(vdev) \
	(struct vgicv2_dev *)container_of(vdev, struct vgicv2_dev, vdev)

#define vdev_to_vgicc(vdev) \
	(struct vgicc *)container_of(vdev, struct vgicc, vdev);

// 从 device_node 中获取中断相关信息
extern int gic_xlate_irq(struct device_node *node,
		uint32_t *intspec, unsigned int initsize,
		uint32_t *hwirq, unsigned long *type);

// 模拟 GICD_ICFGR 寄存器， 
// 获取中断类型
static uint32_t vgicv2_get_virq_type(struct vcpu *vcpu, uint32_t offset)
{
	int i;
	int irq;
	uint32_t value = 0, tmp;

	offset = (offset - GICD_ICFGR) / 4;
	irq = 16 * offset;

	// format 这 16 个 irq 对应的 type
	for (i = 0; i < 16; i++, irq++) {
		tmp = virq_get_type(vcpu, irq);
		value = value | (tmp << i * 2);
	}

	return value;
}

// 设置irq类型，道理同上
static void vgicv2_set_virq_type(struct vcpu *vcpu,
		uint32_t offset, uint32_t value)
{
	int i;
	int irq;

	offset = (offset - GICD_ICFGR) / 4;
	irq = 16 * offset;

	for (i = 0; i < 16; i++, irq++) {
		virq_set_type(vcpu, irq, value & 0x3);
		value = value >> 2;
	}
}


// 获取 irq affinity 亲和性
static uint32_t vgicv2_get_virq_affinity(struct vcpu *vcpu,
		unsigned long offset)
{
	int i;
	int irq;
	uint32_t value = 0, t;

	// 除以 4 表示第几个 GICD_ITARGETSRn
	offset = (offset - GICD_ITARGETSR) / 4;
	irq = 4 * offset;

	for (i = 0; i < 4; i++, irq++) {
		//t 实际为 uint8_t，表示对 8 个 CPU 的亲和性
		t = virq_get_affinity(vcpu, irq);
		//1<<t，表示id形式转换为 one shot 位图形式，这里感觉有点 bug，如果 t 表示多个 CPU 亲和性呢？这里岂不是会溢出？？？
		//32位表示 4 个 irq 的 cpu targets，这里 8 * i 就是放到对应正确的位置上
		value |= (1 << t) << (8 * i);
	}

	return value;
}

// 获取 irq 对应的优先级
static uint32_t vgicv2_get_virq_pr(struct vcpu *vcpu,
		unsigned long offset)
{
	int i;
	uint32_t irq;
	uint32_t value = 0, t;

	// 第几个 GICD_IPRIORITYR 寄存器
	offset = (offset - GICD_IPRIORITYR) / 4;
	// irq number
	irq = offset * 4;

	// format 第 offset 个 GICD_IPRIORITYR 寄存器值
	for (i = 0; i < 4; i++, irq++) {
		t = virq_get_pr(vcpu, irq);
		value |= t << (8 * i);
	}

	return value;
}

// reg 为某个寄存器组编号，这里比如说 GICD_ICENABLER 0x180
static uint32_t inline vgicv2_get_virq_state(struct vcpu *vcpu,
		unsigned long offset, unsigned long reg)
{
	int i;
	uint32_t irq;
	uint32_t value = 0, t;

	// 获取第几个 GICD_ICENABLER 寄存器
	offset = (offset - reg) / 4;
	// irq number
	irq = offset * 32;

	// format GICD_ICENABLER 寄存器值
	for (i = 0; i < 32; i++, irq++) {
		t = virq_get_state(vcpu, irq);
		value |= t << i;
	}

	return value;
}

static uint32_t vgicv2_get_virq_mask(struct vcpu *vcpu,
		unsigned long offset)
{
	return vgicv2_get_virq_state(vcpu, offset, GICD_ICENABLER);
}

static uint32_t vgicv2_get_virq_unmask(struct vcpu *vcpu,
		unsigned long offset)
{
	return vgicv2_get_virq_state(vcpu, offset, GICD_ISENABLER);
}

// 
static int vgicv2_read(struct vcpu *vcpu, struct vgicv2_dev *gic,
		unsigned long offset, unsigned long *v)
{
	uint32_t tmp;
	uint32_t *value = (uint32_t *)v;

	/* to be done */
	switch (offset) {
	// 全局 Distributor 中断使能位，如果为 0，则所有 pending from distributor 的中断都会被屏蔽
	case GICD_CTLR:
		*value = !!gic->gicd_ctlr;
		break;
	// 指示当前 GIC 的一些信息，比如说当前 gic 是否实现了“安全扩展”，gic 支持的最大 interrupt id，cpu interface 实现个数等等
	case GICD_TYPER:
		*value = gic->gicd_typer;
		break;
	// 每一位表示对应 irq 的 group
	case GICD_IGROUPR...GICD_IGROUPRN:
		/* all group 1 */
		*value = 0xffffffff;
		break;
	// 对于SPI和PPI类型的中断，每一位控制对应中断的转发行为：从Distributor转发到CPU interface： 
	// 读： 0：表示当前是禁止转发的； 1：表示当前是使能转发的； 写： 0：无效 1：使能转发
	case GICD_ISENABLER...GICD_ISENABLERN:
		*value = vgicv2_get_virq_unmask(vcpu, offset);
		break;
	// 对于SPI和PPI类型的中断，每一位控制对应中断的转发行为：从Distributor转发到CPU interface： 
	// 读： 0：表示当前是禁止转发的； 1：表示当前是使能转发的； 写： 0：无效 1：禁止转发
	case GICD_ICENABLER...GICD_ICENABLERN:
		*value = vgicv2_get_virq_mask(vcpu, offset);
		break;
	// 中断的 pending 状态
	// 读：0 表示该中断没有 pending 到任何 processor，
	// 读：1，如果为 PPI 和 SGI，表示该中断 pending 到了当前 processor，如果为 SPI，表示该中断至少 pending 到了 1 个 processor 上
	// 这里模拟实现中，全部为 0
	case GICD_ISPENDR...GICD_ISPENDRN:
		*value = 0;
		break;
	// 清零某中断的 pending 状态
	case GICD_ICPENDR...GICD_ICPENDRN:
		*value = 0;
		break;
	// 某中断的 active 中断
	// 读 0，表示该中断处于 not active 状态，读 1，表示该中断处于 active 状态
	// 写 0，无影响
	// 写 1，如果当前中断还未 active，那么 activate 该中断，否则无影响
	// 这里模拟实现中，全部设置为 0
	case GICD_ISACTIVER...GICD_ISACTIVERN:
		*value = 0;
		break;
	// 清零某中断的 active 状态
	case GICD_ICACTIVER...GICD_ICACTIVERN:
		*value = 0;
		break;
	// 获取每个中断的优先级，当然这里读取的是一个寄存器的值，包含了 4 个中断的优先级
	case GICD_IPRIORITYR...GICD_IPRIORITYRN:
		*value = vgicv2_get_virq_pr(vcpu, offset);
		break;
	// 获取某 GICD_ITARGETSR 寄存器里面关于亲和性的值
	// 对于 GICD_ITARGETSR0 ~ GICD_ITARGETSR7，读取会返回当前 CPU 的 id 值
	case GICD_ITARGETSR...GICD_ITARGETSR7:
		tmp = 1 << get_vcpu_id(vcpu);
		*value = tmp;
		*value |= tmp << 8;
		*value |= tmp << 16;
		*value |= tmp << 24;
		break;
	// irq 32 及以后的中断的 cpu 亲和性
	case GICD_ITARGETSR8...GICD_ITARGETSRN:
		*value = vgicv2_get_virq_affinity(vcpu, offset);
		break;
	// 获取 irq 的 type
	case GICD_ICFGR...GICD_ICFGRN:
		*value = vgicv2_get_virq_type(vcpu, offset);
		break;

	// GIC 版本信息，0x2 << 4 表示这是一个 gicv2
	case GICD_ICPIDR2:
		*value = 0x2 << 4;
	}

	return 0;
}

// 发送 sgi 类型的中断给某 vcpu
void vgicv2_send_sgi(struct vcpu *vcpu, uint32_t sgi_value)
{
	int bit;
	sgi_mode_t mode;
	uint32_t sgi;
	cpumask_t cpumask;
	unsigned long list;
	struct vm *vm = vcpu->vm;
	struct vcpu *target;

	// 清空 cpumask
	cpumask_clearall(&cpumask);
	// 获取 sgi_value 中的 cpu list
	list = (sgi_value >> 16) & 0xff;
	sgi = sgi_value & 0xf;
	mode = (sgi_value >> 24) & 0x3;
	if (mode == 0x3) {
		pr_warn("invalid sgi mode\n");
		return;
	}

	// 如果是将 sgi 类型的中断发送给 sgi_value 中的 cpu list
	if (mode == SGI_TO_LIST) {
		// 遍历 list，然后设置 cpumask
		for_each_set_bit(bit, &list, 8)
			cpumask_set_cpu(bit, &cpumask);
	// 如果发送给其他 CPU，这个应该是相当于广播
	} else if (mode == SGI_TO_OTHERS) {
		//遍历该 vm 中的所有其他 vcpu，设置 vcpu
		for (bit = 0; bit < vm->vcpu_nr; bit++) {
			if (bit == vcpu->vcpu_id)
				continue;
			cpumask_set_cpu(bit, &cpumask);
		}
	} else
		// 否则是发送给自己，将 cpumask 设置为自己的 cpu_id
		cpumask_set_cpu(vcpu->vcpu_id, &cpumask);

	// 遍历 cpumask 中的 cpu_id
	for_each_cpu(bit, &cpumask) {
		// 根据 cpu_id，获取对应 vm 中的 vcpu
		target = get_vcpu_in_vm(vm, bit);
		if (target == NULL)
			panic("vcpu%d is not in vm\n", bit);
		// 发送 sgi 给该 vcpu
		send_virq_to_vcpu(target, sgi);
	}
}

// 读 virtual gic v2 进行写操作，原理通 read
static int vgicv2_write(struct vcpu *vcpu, struct vgicv2_dev *gic,
		unsigned long offset, unsigned long *v)
{
	uint32_t x, y, bit, t;
	uint32_t value = *(uint32_t *)v;

	/* to be done */
	switch (offset) {
	case GICD_CTLR:
		gic->gicd_ctlr = value;
		break;
	case GICD_TYPER:
		break;
	case GICD_IGROUPR...GICD_IGROUPRN:
		break;
	case GICD_ISENABLER...GICD_ISENABLERN:
		x = (offset - GICD_ISENABLER) / 4;
		y = x * 32;
		for_each_set_bit(bit, v, 32)
			virq_enable(vcpu, y + bit);
		break;
	case GICD_ICENABLER...GICD_ICENABLERN:
		x = (offset - GICD_ICENABLER) / 4;
		y = x * 32;
		for_each_set_bit(bit, v, 32)
			virq_disable(vcpu, y + bit);
		break;
	case GICD_ISPENDR...GICD_ISPENDRN:
		break;
	case GICD_ICPENDR...GICD_ICPENDRN:
		break;
	case GICD_ISACTIVER...GICD_ISACTIVERN:
		break;
	case GICD_ICACTIVER...GICD_ICACTIVERN:
		break;
	case GICD_IPRIORITYR...GICD_IPRIORITYRN:
		t = value;
		x = (offset - GICD_IPRIORITYR) / 4;
		y = x * 4 - 1;
		bit = (t & 0x000000ff);
		virq_set_priority(vcpu, y + 1, bit);
		bit = (t & 0x0000ff00) >> 8;
		virq_set_priority(vcpu, y + 2, bit);
		bit = (t & 0x00ff0000) >> 16;
		virq_set_priority(vcpu, y + 3, bit);
		bit = (t & 0xff000000) >> 24;
		virq_set_priority(vcpu, y + 4, bit);
		break;
	case GICD_ITARGETSR8...GICD_ITARGETSRN:
		/* to be done */
		break;
	case GICD_ICFGR...GICD_ICFGRN:
		vgicv2_set_virq_type(vcpu, offset, value);
		break;

	case GICD_SGIR:
		vgicv2_send_sgi(vcpu, value);
		break;
	}

	return 0;
}

// vgic 内存映射寄存器 读写 handler
static int vgicv2_mmio_handler(struct vdev *vdev, gp_regs *regs,
		int read, unsigned long offset, unsigned long *value)
{
	struct vcpu *vcpu = get_current_vcpu();
	struct vgicv2_dev *gic = vdev_to_vgicv2(vdev);

	if (read)
		return vgicv2_read(vcpu, gic, offset, value);
	else
		return vgicv2_write(vcpu, gic, offset, value);
}

static int vgicv2_mmio_read(struct vdev *vdev, gp_regs *regs,
		int idx, unsigned long offset, unsigned long *read_value)
{
	return vgicv2_mmio_handler(vdev, regs, 1, offset, read_value);
}

static int vgicv2_mmio_write(struct vdev *vdev, gp_regs *regs,
		int idx, unsigned long offset, unsigned long *write_value)
{
	return vgicv2_mmio_handler(vdev, regs, 0, offset, write_value);
}

static void vgicv2_reset(struct vdev *vdev)
{
	pr_notice("vgicv2 device reset\n");
}

static void vgicv2_deinit(struct vdev *vdev)
{
	struct vgicv2_dev *dev = vdev_to_vgicv2(vdev);

	if (!dev)
		return;

	vdev_release(&dev->vdev);
	free(dev);
}

// 读取 virtual gic cpu interface 相关寄存器
static int vgicc_read(struct vdev *vdev, gp_regs *reg,
		int idx, unsigned long offset, unsigned long *value)
{
	struct vgicc *vgicc = vdev_to_vgicc(vdev);

	switch (offset) {
	// 在 cpu interface 这个 top-level 层级进行中断的屏蔽控制
	// 如果是 0，则屏蔽所有从 distributor 发送到该 cpu interface 的中断，即该 cpu interface 不能想 cpu 发送中断信号
	// 如果是 1，则相反
	case GICC_CTLR:
		*value = vgicc->gicc_ctlr;
		break;
	// Priority Mask Register，中断优先级过滤器
	// 只有中断优先级高于该寄存器值的中断才允许发送给 cpu
	case GICC_PMR:
		*value = vgicc->gicc_pmr;
		break;
	// Binary Point Register，这个寄存器指示如何将 8bit 的 priority value 分割成 group priority value 和 subpriority field，具体见文档
	case GICC_BPR:
		*value = vgicc->gicc_bpr;
		break;
	// 此寄存器存放着当前中断的 irq number
	case GICC_IAR:
		/* get the pending irq number */
		*value = get_pending_virq(get_current_vcpu());
		break;
	// Running Priority Register
	// secure extension 可能会使用，这里直接返回全 0
	case GICC_RPR:
		/* TBD - now fix to 0xa0 */
		*value = 0xa0;
		break;
	// 
	case GICC_HPPIR:
		/* TBD - now fix to 0xa0 */
		*value = 0xa0;
		break;
	// CPU Interface Identification Register
	// 提供了 GICC 本身的一些信息
	// 0x2 表示这是 gicv2
	case GICC_IIDR:
		*value = 0x43b | (0x2 << 16);
		break;
	}

	return 0;
}

// virtual gicc write 函数
static int vgicc_write(struct vdev *vdev, gp_regs *reg,
		int idx, unsigned long offset, unsigned long *value)
{
	struct vgicc *vgicc = vdev_to_vgicc(vdev);

	switch (offset) {
	case GICC_CTLR:
		vgicc->gicc_ctlr = *value;
		break;
	case GICC_PMR:
		vgicc->gicc_pmr = *value;
		break;
	case GICC_BPR:
		vgicc->gicc_bpr = *value;
		break;
	case GICC_EOIR:
		clear_pending_virq(get_current_vcpu(), *value);
		break;
	case GICC_DIR:
		/* if the virq is hw to deactive it TBD */
		break;
	}

	return 0;
}

static void vgicc_reset(struct vdev *vdev)
{
}

static void vgicc_deinit(struct vdev *vdev)
{
	vdev_release(vdev);
	free(vdev);
}

// 创建 virtual gicc 
static int vgicv2_create_vgicc(struct vm *vm, unsigned long base, size_t size)
{
	struct vgicc *vgicc;

	vgicc = zalloc(sizeof(*vgicc));
	if (!vgicc) {
		pr_err("no memory for vgicv2 vgicc\n");
		return -ENOMEM;
	}

	host_vdev_init(vm, &vgicc->vdev, "vgicv2_vgicc");
	if (vdev_add_iomem_range(&vgicc->vdev, base, size)) {
		pr_err("vgicv2: add gicc iomem failed\n");
		free(vgicc);
		return -ENOMEM;
	}

	vgicc->gicc_base = base;
	vgicc->vdev.read = vgicc_read;
	vgicc->vdev.write = vgicc_write;
	vgicc->vdev.reset = vgicc_reset;
	vgicc->vdev.deinit = vgicc_deinit;
	vdev_add(&vgicc->vdev);

	return 0;
}

static inline void writel_gich(uint32_t val, unsigned int offset)
{
	writel_relaxed(val, (void *)vgicv2_info.gich_base + offset);
}

static inline uint32_t readl_gich(int unsigned offset)
{
	return readl_relaxed((void *)vgicv2_info.gich_base + offset);
}

int gicv2_get_virq_state(struct vcpu *vcpu, struct virq_desc *virq)
{
	uint32_t value;

	if (virq->id >= gicv2_nr_lrs)
		return 0;

	value = readl_gich(GICH_LR + virq->id * 4);
	rmb();
	value = (value >> 28) & 0x3;

	return value;
}

// 发送 virq
static int gicv2_send_virq(struct vcpu *vcpu, struct virq_desc *virq)
{
	uint32_t val;
	uint32_t pid = 0;
	struct gich_lr *gich_lr;

	if (virq->id >= gicv2_nr_lrs) {
		pr_err("invalid virq %d\n", virq->id);
		return -EINVAL;
	}

	// 如果该 virtual interrupt 对应着实际的 hardware interrupt
	if (virq_is_hw(virq))
		// 记录 physical interrupt id
		pid = virq->hno;
	
	else {
		// 如果是一个 sgi 类型 virtual interrupt 
		if (virq->vno < 16)
			// lr 中的 bit12-10 表示 requsting cpu id
			pid = virq->src;
	}
	// 构造一个 lr 寄存器值
	gich_lr = (struct gich_lr *)&val;
	gich_lr->vid = virq->vno;
	gich_lr->pid = pid;
	gich_lr->pr = virq->pr;
	gich_lr->grp1 = 0;   //这是一个 group 0 virtual interrupt
	gich_lr->state = 1;   //表示 pending
	gich_lr->hw = !!virq_is_hw(virq);

	writel_gich(val, GICH_LR + virq->id * 4);

	return 0;
}

// 
static int gicv2_update_virq(struct vcpu *vcpu,
		struct virq_desc *desc, int action)
{
	if (!desc || desc->id >= gicv2_nr_lrs)
		return -EINVAL;

	switch (action) {
	case VIRQ_ACTION_REMOVE:
		if (virq_is_hw(desc))
			irq_clear_pending(desc->hno);
	

	case VIRQ_ACTION_CLEAR:
		writel_gich(0, GICH_LR + desc->id * 4);
		break;
	}

	return 0;
}

static int vgicv2_vcpu_init(struct vcpu *vcpu, void *d, unsigned long flags)
{
	if (!(flags & VIRQCHIP_F_HW_VIRT))
		return 0;

	vcpu->virq_struct->nr_lrs = gicv2_nr_lrs;

	return 0;
}

static int vgicv2_init_virqchip(struct virq_chip *vc,
		struct vgicv2_dev *dev, unsigned long flags)
{
	if (flags & VIRQCHIP_F_HW_VIRT) {
		vc->exit_from_guest = vgic_irq_exit_from_guest;
		vc->enter_to_guest = vgic_irq_enter_to_guest;
		vc->send_virq = gicv2_send_virq;
		vc->update_virq = gicv2_update_virq;
		vc->get_virq_state = gicv2_get_virq_state;
	}

	vc->xlate = gic_xlate_irq;
	vc->generate_virq = vgic_generate_virq;
	vc->vcpu_init = vgicv2_vcpu_init;
	vc->flags = flags;

	return 0;
}

// 从 device_node 中获取 gic info
static int get_vgicv2_info(struct device_node *node, struct vgicv2_info *vinfo)
{
	int ret;

	memset(vinfo, 0, sizeof(struct vgicv2_info));
	ret = translate_device_address_index(node, &vinfo->gicd_base,
			&vinfo->gicd_size, 0);
	if (ret) {
		pr_err("no gicv3 address info found\n");
		return -ENOENT;
	}

	ret = translate_device_address_index(node, &vinfo->gicc_base,
			&vinfo->gicc_size, 1);
	if (ret) {
		pr_err("no gicc address info found\n");
		return -ENOENT;
	}

	if (vinfo->gicd_base == 0 || vinfo->gicd_size == 0 ||
			vinfo->gicc_base == 0 || vinfo->gicc_size == 0) {
		pr_err("gicd or gicc address info not correct\n");
		return -EINVAL;
	}

	translate_device_address_index(node, &vinfo->gich_base,
			&vinfo->gich_size, 2);
	translate_device_address_index(node, &vinfo->gicv_base,
			&vinfo->gicv_size, 3);

	pr_notice("vgicv2: address 0x%x 0x%x 0x%x 0x%x\n",
			vinfo->gicd_base, vinfo->gicd_size,
			vinfo->gicc_base, vinfo->gicc_size);

	return 0;

}

// virtual gic chip init
static struct virq_chip *vgicv2_virqchip_init(struct vm *vm,
		struct device_node *node)
{
	int ret, flags = 0;
	struct vgicv2_dev *dev;
	struct virq_chip *vc;
	struct vgicv2_info vinfo;

	pr_notice("create vgicv2 for vm-%d\n", vm->vmid);

	// 从 device node 中获取 vgic 的一些信息
	ret = get_vgicv2_info(node, &vinfo);
	if (ret) {
		pr_err("no gicv2 address info found\n");
		return NULL;
	}
	// 分配 vgicv2_dev 结构体
	dev = zalloc(sizeof(struct vgicv2_dev));
	if (!dev)
		return NULL;

	// 设置 gic distributor 基址
	dev->gicd_base = vinfo.gicd_base;
	// 初始化虚拟设备 virtual gicv2
	host_vdev_init(vm, &dev->vdev, "vgicv2");
	// 添加虚拟设备的内存映射区域
	ret = vdev_add_iomem_range(&dev->vdev, vinfo.gicd_base, vinfo.gicd_size);
	if (ret)
		goto release_vdev;
	
	// 表示实现的 cpu interface 数量，也就是 cpu 数量
	dev->gicd_typer = vm->vcpu_nr << 5; 
	// 表示 ITLinesNumber，支持的最大中断数 = (ITLinesNumber + 1) * 32
	dev->gicd_typer |= (vm->vspi_nr >> 5) - 1; 
	// gicd 的一些信息，设置为 0
	dev->gicd_iidr = 0x0;

	// 设置该 virtual gic 的一些操作函数
	dev->vdev.read = vgicv2_mmio_read;
	dev->vdev.write = vgicv2_mmio_write;
	dev->vdev.deinit = vgicv2_deinit;
	dev->vdev.reset = vgicv2_reset;
	// 注册该 vgic，即添加到 vm 的 vdev_list
	vdev_add(&dev->vdev);

	// 分配一个 virq_chip 结构体
	vc = alloc_virq_chip();
	if (!vc)
		goto release_vdev;

	/*
	 * if the gicv base is set indicate that
	 * platform has a hardware gicv2, otherwise
	 * we need to emulated the trap.
	 */
	// 如果不是 SWE，表明该平台有硬件 gicv2，创建相应的内存映射
	if (vgicv2_mode != VGICV2_MODE_SWE) {
		flags |= VIRQCHIP_F_HW_VIRT;
		pr_notice("map gicc 0x%x to gicv 0x%x size 0x%x\n",
				vinfo.gicc_base, vgicv2_info.gicv_base,
				vinfo.gicc_size);
		create_guest_mapping(&vm->mm, vinfo.gicc_base,
				vgicv2_info.gicv_base, vinfo.gicc_size,
				VM_GUEST_IO | VM_RW);
	// 否则就应该创建一个 gicc
	} else {
		ret = vgicv2_create_vgicc(vm, vinfo.gicc_base, vinfo.gicc_size);
		if (ret)
			goto release_vgic;
	}

	vc->inc_pdata = dev;
	vgicv2_init_virqchip(vc, dev, flags);

	return vc;

release_vgic:
	free(vc);
release_vdev:
	vdev_release(&dev->vdev);
	free(dev);

	return NULL;
}
VIRQCHIP_DECLARE(gic400_virqchip, gicv2_match_table,
		vgicv2_virqchip_init);

// 恢复 gicv2 的上下文
static void gicv2_state_restore(struct vcpu *vcpu, void *context)
{
	int i;
	struct gicv2_context *c = (struct gicv2_context *)context;

	// 恢复所有的 lr 寄存器
	for (i = 0; i < gicv2_nr_lrs; i++)
		writel_gich(c->lr[i], GICH_LR + i * 4);

	writel_gich(c->apr, GICH_APR);
	writel_gich(c->vmcr, GICH_VMCR);
	writel_gich(c->hcr, GICH_HCR);
}

static void gicv2_state_init(struct vcpu *vcpu, void *context)
{
	struct gicv2_context *c = (struct gicv2_context *)context;

	memset(c, 0, sizeof(*c));
	c->hcr = 1;
}

// 保存 gicv2 的上下文到 context 
static void gicv2_state_save(struct vcpu *vcpu, void *context)
{
	int i;
	struct gicv2_context *c = (struct gicv2_context *)context;

	dsb();

	for (i = 0; i < gicv2_nr_lrs; i++)
		c->lr[i] = readl_gich(GICH_LR + i * 4);

	c->vmcr = readl_gich(GICH_VMCR);
	c->apr = readl_gich(GICH_APR);
	c->hcr = readl_gich(GICH_HCR);
	writel_gich(0, GICH_HCR);
}

static void gicv2_state_resume(struct vcpu *vcpu, void *context)
{
	gicv2_state_init(vcpu, context);
}

static int gicv2_vmodule_init(struct vmodule *vmodule)
{
	vmodule->context_size = sizeof(struct gicv2_context);
	vmodule->state_init = gicv2_state_init;
	vmodule->state_save = gicv2_state_save;
	vmodule->state_restore = gicv2_state_restore;
	vmodule->state_resume = gicv2_state_resume;

	return 0;
}

// virtual gicv2 init
int vgicv2_init(uint64_t *data, int len)
{
	unsigned long *value = (unsigned long *)&vgicv2_info;
	uint32_t vtr;
	int i;

	if ((data == NULL) || (len == 0)) {
		pr_notice("vgicv2 using software emulation mode\n");
		vgicv2_mode = VGICV2_MODE_SWE;
		return 0;
	}

	for (i = 0; i < len; i++) {
		value[i] = data[i];
		if (value[i] == 0) {
			pr_err("invalid vgicv2 address, fallback to SWE mode\n");
			vgicv2_mode = VGICV2_MODE_SWE;
			return 0;
		}
	}

	if (vgicv2_info.gicv_base == 0) {
		pr_warn("no gicv base address, fall back to SWE mode\n");
		vgicv2_mode = VGICV2_MODE_SWE;
		return 0;
	}

	vtr = readl_relaxed((void *)vgicv2_info.gich_base + GICH_VTR);
	gicv2_nr_lrs = (vtr & 0x3f) + 1;
	pr_notice("vgicv2: nr_lrs %d\n", gicv2_nr_lrs);

	// 创建一个 vmodule
	register_vcpu_vmodule("vgicv2", gicv2_vmodule_init);

	return 0;
}
