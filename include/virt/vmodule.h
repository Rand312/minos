#ifndef _MINOS_MODULE_H_
#define _MINOS_MODULE_H_

#include <minos/types.h>
#include <minos/list.h>
#include <minos/device_id.h>

struct vcpu;

#define INVALID_MODULE_ID (-1)

struct vmodule {
	char name[32];    // 该 vmodule 的名称
	int id;           
	struct list_head list;   // 挂入 vmodule_list 的字段
	uint32_t context_size;   // 该 vmodule 管理的数据大小

	/*
	 * below member usually used for vcpu
	 *
	 * state_save - save the context when sched out
	 * state_restore - restore the context when sched in
	 * state_init - init the state when the vcpu is create
	 * state_deinit - destroy the state when the vcpu is releas
	 * state_reset - reset the state when the vcpu is reset
	 * state_stop - stop the state when the vcpu is stop
	 * state_suspend - suspend the state when the vcpu suspend
	 * state_resume - resume the state when the vcpu is resume
	 */
	void (*state_save)(struct vcpu *vcpu, void *context);
	void (*state_restore)(struct vcpu *vcpu, void *context);
	void (*state_init)(struct vcpu *vcpu, void *context);
	void (*state_deinit)(struct vcpu *vcpu, void *context);
	void (*state_reset)(struct vcpu *vcpu, void *context);
	void (*state_stop)(struct vcpu *vcpu, void *context);
	void (*state_suspend)(struct vcpu *vcpu, void *context);
	void (*state_resume)(struct vcpu *vcpu, void *context);
	void (*state_dump)(struct vcpu *vcpu, void *context);
};

typedef int (*vmodule_init_fn)(struct vmodule *);

int vcpu_vmodules_init(struct vcpu *vcpu);
int vcpu_vmodules_deinit(struct vcpu *vcpu);

void reset_vcpu_vmodule_state(struct vcpu *vcpu);
void save_vcpu_vmodule_state(struct vcpu *vcpu);
void restore_vcpu_vmodule_state(struct vcpu *vcpu);
void suspend_vcpu_vmodule_state(struct vcpu *vcpu);
void resume_vcpu_vmodule_state(struct vcpu *vcpu);
void stop_vcpu_vmodule_state(struct vcpu *vcpu);
void dump_vcpu_vmodule_state(struct vcpu *vcpu);

void *get_vmodule_data_by_id(struct vcpu *vcpu, int id);
int register_vcpu_vmodule(const char *name, vmodule_init_fn fn);

#endif
