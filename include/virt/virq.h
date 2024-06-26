#ifndef __MINOS_VIRQ_H__
#define __MINOS_VIRQ_H__

#include <virt/vm.h>
#include <minos/cpumask.h>
#include <config/config.h>

struct irqtag;

#define VIRQ_STATE_INACTIVE		(0x0)
#define VIRQ_STATE_PENDING		(0x1)
#define VIRQ_STATE_ACTIVE		(0x2)
#define VIRQ_STATE_ACTIVE_AND_PENDING	(0x3)

#define VCPU_MAX_ACTIVE_VIRQS		(64)
#define VIRQ_INVALID_ID			(0xff)

#define VIRQ_ACTION_REMOVE	(0x0)
#define VIRQ_ACTION_ADD		(0x1)
#define VIRQ_ACTION_CLEAR	(0x2)

#define VIRQ_AFFINITY_VM_ANY	(0xff)
#define VIRQ_AFFINITY_VCPU_ANY	(0xff)

#define VM_SGI_VIRQ_NR		(CONFIG_NR_SGI_IRQS)   //16
#define VM_PPI_VIRQ_NR		(CONFIG_NR_PPI_IRQS)   //16
#define VM_LOCAL_VIRQ_NR	(VM_SGI_VIRQ_NR + VM_PPI_VIRQ_NR)

#ifndef CONFIG_HVM_SPI_VIRQ_NR
#define HVM_SPI_VIRQ_NR		(384)
#else
#define HVM_SPI_VIRQ_NR		CONFIG_HVM_SPI_VIRQ_NR
#endif

#define HVM_SPI_VIRQ_BASE	(VM_LOCAL_VIRQ_NR)

#ifndef CONFIG_GVM_SPI_VIRQ_NR
#define GVM_SPI_VIRQ_NR		(64)
#else
#define GVM_SPI_VIRQ_NR		CONFIG_GVM_SPI_VIRQ_NR
#endif

#define GVM_SPI_VIRQ_BASE	(VM_LOCAL_VIRQ_NR)

#define VIRQ_SPI_OFFSET(virq)	((virq) - VM_LOCAL_VIRQ_NR)
#define VIRQ_SPI_NR(count)	((count) > VM_LOCAL_VIRQ_NR ? VIRQ_SPI_OFFSET((count)) : 0)

#define VM_VIRQ_NR(nr)		((nr) + VM_LOCAL_VIRQ_NR)

#define MAX_HVM_VIRQ		(HVM_SPI_VIRQ_NR + VM_LOCAL_VIRQ_NR)
#define MAX_GVM_VIRQ		(GVM_SPI_VIRQ_NR + VM_LOCAL_VIRQ_NR)

#define VIRQS_NEED_EXPORT_BIT	(0)
#define VIRQS_ENABLED_BIT 	(1)
#define VIRQS_SUSPEND_BIT	(2)
#define VIRQS_HW_BIT		(3)
#define VIRQS_CAN_WAKEUP_BIT	(4)
#define VIRQS_REQUESTED_BIT	(6)
#define VIRQS_FIQ_BIT		(7)

#define VIRQS_NEED_EXPORT	(1 << VIRQS_NEED_EXPORT_BIT)
#define VIRQS_ENABLED		(1 << VIRQS_ENABLED_BIT)
#define VIRQS_SUSPEND		(1 << VIRQS_SUSPEND_BIT)
#define VIRQS_HW		(1 << VIRQS_HW_BIT)
#define VIRQS_CAN_WAKEUP	(1 << VIRQS_CAN_WAKEUP_BIT)
#define VIRQS_REQUESTED		(1 << VIRQS_REQUESTED_BIT)
#define VIRQS_FIQ		(1 << VIRQS_FIQ_BIT)

#define VIRQF_CAN_WAKEUP	VIRQS_CAN_WAKEUP
#define VIRQF_ENABLE		VIRQS_ENABLED
#define VIRQF_FIQ		VIRQS_FIQ
#define VIRQF_NEED_EXPORT	VIRQS_NEED_EXPORT

#define FIQ_HAS_INJECT		(1 << 31)

struct virq_desc {
	int32_t flags;
	uint16_t vno;    // virq number
	uint16_t hno;    // 如果该 virq 关联了一个 hwirq，记录该 hwirq number
	uint8_t id;      // LR 寄存器编号
	uint8_t state;   // 状态
	uint8_t pr;      // 优先级
	uint8_t src;     // SGI 中断下，记录源 vcpu id
	uint8_t type;    // edge or level
	uint8_t vcpu_id; // vcpu id
	uint8_t vmid;    // vm id
	uint8_t padding;
} __packed;

#define VGIC_MAX_LRS 128

struct virq_struct {
	int nr_lrs;           // LR 寄存器个数
	int last_fail_virq;   // 上一个因分配 LR 失败的 virq
	atomic_t pending_virq;  // 有多少个 virq 处于 pending 状态
	uint32_t active_virq;   // 有多少个 virq 处于 active 状态
	struct virq_desc local_desc[VM_LOCAL_VIRQ_NR];  // virq 描述符(PPI+SGI)
	unsigned long *pending_bitmap;  // virq pending 位图（PPI+SGI+SPI)
	unsigned long *active_bitmap;  // virq active 位图
	unsigned long lrs_bitmap[BITS_TO_LONGS(VGIC_MAX_LRS)];  // LR 位图
};

static inline int vm_irq_count(struct vm *vm)
{
	return vm->vspi_nr + VM_LOCAL_VIRQ_NR;
}

static void inline virq_set_enable(struct virq_desc *d)
{
	d->flags |= VIRQS_ENABLED;
}

static void inline virq_clear_enable(struct virq_desc *d)
{
	d->flags &= ~VIRQS_ENABLED;
}

static int inline virq_is_enabled(struct virq_desc *d)
{
	return !!(d->flags & VIRQS_ENABLED);
}

static void inline virq_set_wakeup(struct virq_desc *d)
{
	d->flags |= VIRQS_CAN_WAKEUP;
}

static void inline virq_clear_wakeup(struct virq_desc *d)
{
	d->flags &= ~VIRQS_CAN_WAKEUP;
}

static int inline virq_can_wakeup(struct virq_desc *d)
{
	return !!(d->flags & VIRQS_CAN_WAKEUP);
}

static void inline virq_set_suspend(struct virq_desc *d)
{
	d->flags |= VIRQS_SUSPEND;
}

static void inline virq_clear_suspend(struct virq_desc *d)
{
	d->flags &= ~VIRQS_SUSPEND;
}

static int inline virq_is_suspend(struct virq_desc *d)
{
	return !!(d->flags & VIRQS_SUSPEND);
}

static void inline virq_set_hw(struct virq_desc *d)
{
	d->flags |= VIRQS_HW;
}

static void inline virq_clear_hw(struct virq_desc *d)
{
	d->flags &= ~VIRQS_HW;
}

static int inline virq_is_hw(struct virq_desc *d)
{
	return !!(d->flags & VIRQS_HW);
}

static int inline virq_is_requested(struct virq_desc *d)
{
	return !!(d->flags & VIRQS_REQUESTED);
}

static void inline __virq_set_fiq(struct virq_desc *d)
{
	d->flags |= VIRQS_FIQ;
}

static int inline virq_is_fiq(struct virq_desc *d)
{
	return !!(d->flags & VIRQS_FIQ);
}

static void inline virq_clear_fiq(struct virq_desc *d)
{
	d->flags &= ~VIRQS_FIQ;
}

int virq_enable(struct vcpu *vcpu, uint32_t virq);
int virq_disable(struct vcpu *vcpu, uint32_t virq);
void vcpu_virq_struct_init(struct vcpu *vcpu);
void vcpu_virq_struct_reset(struct vcpu *vcpu);

void vm_virq_reset(struct vm *vm);
void send_vsgi(struct vcpu *sender,
		uint32_t sgi, cpumask_t *cpumask);
void clear_pending_virq(struct vcpu *vcpu, uint32_t irq);

int virq_set_priority(struct vcpu *vcpu, uint32_t virq, int pr);
int virq_set_type(struct vcpu *vcpu, uint32_t virq, int value);
uint32_t virq_get_type(struct vcpu *vcpu, uint32_t virq);
uint32_t virq_get_affinity(struct vcpu *vcpu, uint32_t virq);
uint32_t virq_get_pr(struct vcpu *vcpu, uint32_t virq);
uint32_t virq_get_state(struct vcpu *vcpu, uint32_t virq);
int virq_can_request(struct vcpu *vcpu, uint32_t virq);
int virq_need_export(struct vcpu *vcpu, uint32_t virq);
uint32_t get_pending_virq(struct vcpu *vcpu);
int virq_set_fiq(struct vcpu *vcpu, uint32_t virq);

int send_virq_to_vcpu(struct vcpu *vcpu, uint32_t virq);
int send_virq_to_vm(struct vm *vm, uint32_t virq);

int vcpu_has_irq(struct vcpu *vcpu);

int alloc_vm_virq(struct vm *vm);
void release_vm_virq(struct vm *vm, int virq);

int request_virq_affinity(struct vm *vm, uint32_t virq,
		uint32_t hwirq, int affinity, unsigned long flags);
int request_hw_virq(struct vm *vm, uint32_t virq, uint32_t hwirq,
			unsigned long flags);
int request_virq_pervcpu(struct vm *vm, uint32_t virq,
			unsigned long flags);
int request_virq(struct vm *vm, uint32_t virq, unsigned long flags);

struct virq_desc *get_virq_desc(struct vcpu *vcpu, uint32_t virq);

static inline int alloc_hvm_virq(void)
{
	return alloc_vm_virq(get_host_vm());
}

static inline int alloc_gvm_virq(struct vm *vm)
{
	return alloc_vm_virq(vm);
}

static void inline release_hvm_virq(int virq)
{
	return release_vm_virq(get_host_vm(), virq);
}

static void inline release_gvm_virq(struct vm *vm, int virq)
{
	return release_vm_virq(vm, virq);
}

struct virq_chip *alloc_virq_chip(void);
int virqchip_get_virq_state(struct vcpu *vcpu, struct virq_desc *virq);
void virqchip_send_virq(struct vcpu *vcpu, struct virq_desc *virq);
void virqchip_update_virq(struct vcpu *vcpu,
		struct virq_desc *virq, int action);

#endif
