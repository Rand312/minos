#ifndef __MVM_VIRT_IO_H_
#define __MVM_VIRT_IO_H_

#include <sys/types.h>
#include <inttypes.h>
#include <minos/vdev.h>
#include <minos/io.h>
#include <generic/virtio_mmio.h>
#include <minos/barrier.h>

#define VRING_DESC_F_NEXT		(1)
#define VRING_DESC_F_WRITE		(2)
#define VRING_DESC_F_INDIRECT		(4)

#define VRING_ALIGN_SIZE		(4096)

#define VRING_AVAIL_F_NO_INTERRUPT	1
#define VRING_USED_F_NO_NOTIFY		1

#define VIRTIO_RING_F_INDIRECT_DESC	28
#define VIRTIO_RING_F_EVENT_IDX		29

#define VIRTIO_F_NOTIFY_ON_EMPTY	24
#define VIRTIO_F_ANY_LAYOUT		27
#define VIRTIO_F_VERSION_1		32

#define VRING_AVAIL_ALIGN_SIZE		2
#define VRING_USED_ALIGN_SIZE		4
#define VRING_DESC_ALIGN_SIZE		16

#define VIRTIO_MMIO_MAGIG		(0x74726976)
#define VIRTIO_VENDER_ID		(0x8888)
#define VIRTIO_VERSION			(0x2)

#define	VIRTIO_TYPE_NET			1
#define	VIRTIO_TYPE_BLOCK		2
#define	VIRTIO_TYPE_CONSOLE		3
#define	VIRTIO_TYPE_ENTROPY		4
#define	VIRTIO_TYPE_BALLOON		5
#define	VIRTIO_TYPE_IOMEMORY		6
#define	VIRTIO_TYPE_RPMSG		7
#define	VIRTIO_TYPE_SCSI		8
#define	VIRTIO_TYPE_9P			9
#define	VIRTIO_TYPE_INPUT		18

#define VIRTIO_DEV_STATUS_ACK		(1)
#define VIRTIO_DEV_STATUS_DRIVER	(2)
#define VIRTIO_DEV_STATUS_OK		(4)
#define VIRTIO_DEV_STATUS_FEATURES_OK	(8)
#define VIRTIO_DEV_NEEDS_RESET		(64)
#define VIRTIO_DEV_STATUS_FAILED	(128)

#define VIRTQUEUE_MAX_SIZE		(1024)
#define VIRTIO_MAX_FEATURE_SIZE		(4)

#define u32_to_u64(high, low) \
	(((uint64_t)(high) << 32) | (low))

#define u16_to_u32(high, low) \
	(((unsigned long)(high) << 16) | (low))


// 往 vring_desc 表只能够存放 IO 请求，
// vring_avail 指明哪些 vring_desc 可以使用
// vring_used 指明哪些 vring_desc 已经被提交给硬件，可以释放了


struct vring_used_elem {
	uint32_t id;   // 表示处理完成的 IO 请求在 vring_desc 表中链表头的位置
	uint32_t len;  // 表示链表的长度
} __packed;

// 指明 vring_desc 中哪些项已经被递交给硬件
struct vring_used {
	uint16_t flags; 
	uint16_t idx;   // 指示 ring 数组中下一个可用的位置
	struct vring_used_elem ring[];
} __packed;

// 指明 vring_desc 中哪些项是可以使用的，意思是说哪些项组成的链表是需要处理的
struct vring_avail {
	uint16_t flags;	   // 标志域
	uint16_t idx;      // 指向 ring 数组中下一个可用的空闲位置
	uint16_t ring[];   // 通过 next 域连接起来的链表的表头在 vring_desc 表中的位置，
					   // 每一项都表示一个空闲链表的表头
} __packed;

// 描述虚拟机产生的 IO 请求的地址
struct vring_desc 
{
	uint64_t addr;  // 存储 IO 请求在虚拟机内的地址，是一个 GPA 值
	uint32_t len;   // 当 desc 描述符作为节点连接一个描述符表的时候，描述符项的个数为 len/sizeof(vring_desc)
	uint16_t flags; // 指示数据的可读写性，是否是请求的最后一项
	uint16_t next;  // 每个 IO 请求都可能包含 vring_desc 表中的多行，next 指明这个请求的下一行在哪
					// 所以通过 next，将一个 IO 请求在 vring_desc 中存储的多行连接成一个链表，
					// 当 flag = ~VRING_DESC_F_NEXT 的时候，这个链表就到了末尾
} __packed;



struct virtio_device;

// 
struct virt_queue {
	int ready;
	unsigned int num;          // descs 表中表项的个数
	unsigned int iovec_size;
	struct vring_desc *desc;   // desc 表
	struct vring_avail *avail; // 待处理头结点表
	struct vring_used *used;   // 已处理的头结点表
	uint16_t last_avail_idx;   // 上次写入的最后一个 avail_ring 的索引
							   // 表示上次最后使用的头结点 desc 下标
	uint16_t avail_idx;
	uint16_t last_used_idx;
	uint16_t used_flags;
	uint16_t signalled_used;
	uint16_t signalled_used_valid;   // false 表示还没有向前端做任何通知
	uint16_t vq_index;

	struct virtio_device *dev;
	struct iovec *iovec;

	void (*callback)(struct virt_queue *);
};

#define virtq_used_event(vq) \
	(uint16_t *)&vq->avail->ring[vq->num]
#define virtq_avail_event(vq) \
	(uint16_t *)&vq->used->ring[vq->num]

struct virtio_ops {
	int (*vq_init)(struct virt_queue *);
	int (*vq_reset)(struct virt_queue *);
	void (*vq_deinit)(struct virt_queue *);
	void (*neg_features)(struct virtio_device *);
};

struct virtio_device {
	struct vdev *vdev;
	struct virt_queue *vqs;
	int nr_vq;
	uint64_t acked_features;
	void *config;
	struct virtio_ops *ops;
};

// 
static int inline virtq_has_descs(struct virt_queue *vq)
{
	return vq->avail->idx != vq->last_avail_idx;
}

static int inline virtq_need_event(uint16_t event_idx,
		uint16_t new_idx, uint16_t old_idx)
{
	return (uint16_t)(new_idx - event_idx - 1) <
				(uint16_t)(new_idx - old_idx);
}

static inline uint32_t vring_size (unsigned int qsz)
{
	return ALIGN((sizeof(struct vring_desc) * qsz) +
		 (sizeof(uint16_t) * (2 + qsz)), VRING_ALIGN_SIZE) +
	       ALIGN(sizeof(struct vring_used_elem) * qsz, VRING_ALIGN_SIZE);
}

static inline void
virtio_set_feature(struct virtio_device *dev, uint32_t feature)
{
	uint32_t value;
	int index = feature / 32;

	if (index >= VIRTIO_MAX_FEATURE_SIZE) {
		pr_warn("invaild feature bit %d\n", feature);
		return;
	}

	value = ioread32(dev->vdev->iomem + VIRTIO_FEATURE_OFFSET(index));
	value |= (1 << (feature % 32));
	iowrite32(dev->vdev->iomem + VIRTIO_FEATURE_OFFSET(index), value);
}

// 用于检查 virtio 设备是否支持某个特性
static int inline virtq_has_feature(struct virt_queue *vq, int fe)
{
	return !!(vq->dev->acked_features & (1UL << fe));
}

static inline void virtio_send_irq(struct virtio_device *dev, int type)
{
	uint32_t value = 0;

	value = ioread32(dev->vdev->iomem + VIRTIO_MMIO_INTERRUPT_STATUS);
	rmb();
	value |= type;
	iowrite32(dev->vdev->iomem + VIRTIO_MMIO_INTERRUPT_STATUS, value);
	wmb();

	vdev_send_irq(dev->vdev);
}

int virtio_device_init(struct virtio_device *,
		struct vdev *, int, int, int, int);
int virtq_enable_notify(struct virt_queue *vq);
void virtq_disable_notify(struct virt_queue *vq);

int virtio_handle_mmio(struct virtio_device *dev, int write,
		uint64_t addr, uint64_t *value);

int virtq_get_descs(struct virt_queue *vq,
		struct iovec *iov, unsigned int iov_size,
		unsigned int *in_num, unsigned int *out_num);

void virtq_discard_desc(struct virt_queue *vq, int n);

int virtq_add_used_n(struct virt_queue *vq,
			struct vring_used_elem *heads,
			unsigned int count);

int virtq_add_used(struct virt_queue *vq,
		unsigned int head, uint32_t len);

void virtq_notify(struct virt_queue *vq);

void virtq_add_used_and_signal(struct virt_queue *vq,
		unsigned int head, int len);

void virtq_add_used_and_signal_n(struct virt_queue *vq,
				struct vring_used_elem *heads,
				unsigned int count);

int virtio_device_reset(struct virtio_device *dev);
void virtio_device_deinit(struct virtio_device *dev);

#endif
