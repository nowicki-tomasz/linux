#include <linux/cpu.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/uaccess.h>

#include <linux/irqchip/arm-gic.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>
#include <kvm/arm_vgic.h>

#include "vgic.h"
#include "vgic-mmio.h"

void *vcpu_prev_shadow_state(struct kvm_vcpu *vcpu)
{

	if (kvm_vgic_global_state.type == VGIC_V3)
		return vcpu->arch.vgic_cpu.prev_shadow_vgic_v3_lr;
	else
		return vcpu->arch.vgic_cpu.prev_shadow_vgic_v2_lr;
}

void *vcpu_nested_if(struct kvm_vcpu *vcpu)
{

	if (kvm_vgic_global_state.type == VGIC_V3)
		return &vcpu->arch.vgic_cpu.nested_vgic_v3;
	else
		return &vcpu->arch.vgic_cpu.nested_vgic_v2;
}

void *vcpu_shadow_if(struct kvm_vcpu *vcpu)
{

	if (kvm_vgic_global_state.type == VGIC_V3)
		return &vcpu->arch.vgic_cpu.shadow_vgic_v3;
	else
		return &vcpu->arch.vgic_cpu.shadow_vgic_v2;
}

void vgic_setup_shadow_state(struct kvm_vcpu *vcpu)
{

	if (kvm_vgic_global_state.type == VGIC_V3)
		vgic_v3_setup_shadow_state(vcpu);
	else
		vgic_v2_setup_shadow_state(vcpu);
}

void vgic_restore_shadow_state(struct kvm_vcpu *vcpu)
{

	if (kvm_vgic_global_state.type == VGIC_V3)
		vgic_v3_restore_shadow_state(vcpu);
	else
		vgic_v2_restore_shadow_state(vcpu);
}

void vgic_propagate_eoi(struct kvm_vcpu *vcpu)
{

	if (kvm_vgic_global_state.type == VGIC_V3)
		vgic_v3_propagate_eoi(vcpu);
	else
		vgic_v2_propagate_eoi(vcpu);
}

void vgic_handle_nested_maint_irq(struct kvm_vcpu *vcpu)
{

	if (kvm_vgic_global_state.type == VGIC_V3)
		vgic_v3_handle_nested_maint_irq(vcpu);
	else
		vgic_v2_handle_nested_maint_irq(vcpu);
}

void vgic_init_nested(struct kvm_vcpu *vcpu)
{

	pr_err("%s init of nsted gicv !!!!!!!!!!\n", __func__);

	if (kvm_vgic_global_state.type == VGIC_V3) {
		pr_err("%s init of nsted gicv V3 !!!!!!!!!!\n", __func__);
		vgic_v3_init_nested(vcpu);
	} else {
		pr_err("%s init of nsted gicv V2 !!!!!!!!!!\n", __func__);
		vcpu->arch.vgic_cpu.vgic_v3.vgic_sre = 0;
		vgic_v2_init_nested(vcpu);
	}
}
