#include <linux/cpu.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/uaccess.h>

#include <linux/irqchip/arm-gic-v3.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_arm.h>
#include <asm/kvm_mmu.h>
#include <kvm/arm_vgic.h>

#include "vgic.h"
#include "vgic-mmio.h"

#define CREATE_TRACE_POINTS
#include "vgic-nested-trace.h"

/*
 * For LRs which have HW bit set such as timer interrupts, we modify them to
 * have the host hardware interrupt number instead of the virtual one programmed
 * by the guest hypervisor.
 */
static void vgic_v3_create_shadow_lr(struct kvm_vcpu *vcpu)
{
	int i;
	struct vgic_v3_cpu_if *cpu_if = vcpu_nested_if(vcpu);
	struct vgic_v3_cpu_if *s_cpu_if = vcpu_shadow_if(vcpu);
	u32 *prev_shadow_state = vcpu_prev_shadow_state(vcpu);
	struct vgic_irq *irq;

	int nr_lr = kvm_vgic_global_state.nr_lr;

	for (i = 0; i < nr_lr; i++) {
		u64 lr = cpu_if->vgic_lr[i];
		int l1_irq;

		prev_shadow_state[i] = 0;
		if (!(lr & ICH_LR_HW))
			goto next;

		/* We have the HW bit set */
		l1_irq = (lr & ICH_LR_PHYS_ID_MASK) >> ICH_LR_PHYS_ID_SHIFT;
		irq = vgic_get_irq(vcpu->kvm, vcpu, l1_irq);

		if (!irq->hw) {
			/* There was no real mapping, so nuke the HW bit */
			lr &= ~ICH_LR_HW;
			vgic_put_irq(vcpu->kvm, irq);
			goto next;
		}

		/* Translate the virtual mapping to the real one */
		lr &= ~ICH_LR_EOI;
		lr &= ~ICH_LR_PHYS_ID_MASK;
		lr |= ((u64)irq->hwintid) << ICH_LR_PHYS_ID_SHIFT;
		vgic_put_irq(vcpu->kvm, irq);

next:
		s_cpu_if->vgic_lr[i] = lr;
		prev_shadow_state[i] = lr;
	}

	trace_vgic_create_shadow_lrs(vcpu, nr_lr,
				     s_cpu_if->vgic_lr, cpu_if->vgic_lr);
}

/*
 * If a nested OS deactivated a virtual interrupt, which is associated with
 * a hardware interrupt (i.e. HW bit set by the guest hypervisor), then
 * we reflect this to the virtual distributor for the guest hypervisor.
 * This is equivalent to the interrupt state change made to the physical
 * distributor by hardware in the non-nesting case.
 */
static void __vgic_propagate_eoi(struct kvm_vcpu *vcpu, u32 val)
{
	struct vgic_v3_cpu_if *cpu_if = &vcpu->arch.vgic_cpu.vgic_v3;
	int nr_lr = kvm_vgic_global_state.nr_lr;
	int i;
	int phys_id, virt_id;

	phys_id = (val & ICH_LR_PHYS_ID_MASK) >> ICH_LR_PHYS_ID_SHIFT;

	/*
	 * We change LRs for the guest hypervisor, since LR states are not
	 * synced back to the AP list at this point.
	 */
	for (i = 0; i < nr_lr; i++) {
		virt_id = cpu_if->vgic_lr[i] & ICH_LR_VIRTUAL_ID_MASK;
		if (virt_id == phys_id) {
			cpu_if->vgic_lr[i] &= ~ICH_LR_ACTIVE_BIT;
			return;
		}
	}
}

/* Assume that shadow_if has the latest lr states and cpu_if has
 * the original phys_id */
void vgic_v3_propagate_eoi(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_v3_cpu_if *cpu_if = vcpu_nested_if(vcpu);
	struct vgic_v3_cpu_if *s_cpu_if = vcpu_shadow_if(vcpu);
	int nr_lr = kvm_vgic_global_state.nr_lr;
	int i;
	int lr;
	bool was_active;
	bool now_active;
	u32 *prev_shadow_state = vcpu_prev_shadow_state(vcpu);

	/* Not using shadow state: Nothing to do... */
	if (vgic_cpu->hw_v3_cpu_if == &vgic_cpu->vgic_v3)
		return;

	for (i = 0; i < nr_lr; i++) {
		lr = s_cpu_if->vgic_lr[i];
		lr &= ~ICH_LR_PHYS_ID_MASK;
		lr |= cpu_if->vgic_lr[i] & ICH_LR_PHYS_ID_MASK;

		if (ICH_LR_HW & lr) {
			was_active =  (ICH_LR_ACTIVE_BIT & prev_shadow_state[i])? true : false;
			now_active =  (ICH_LR_ACTIVE_BIT & lr)? true : false;
			if (was_active && !now_active)
				__vgic_propagate_eoi(vcpu, lr);
		}
	}
}
/*
 * Change the shadow HWIRQ field back to the virtual value before copying over
 * the entire shadow struct to the nested state.
 */
static void vgic_v3_restore_shadow_lr(struct kvm_vcpu *vcpu)
{
	struct vgic_v3_cpu_if *cpu_if = vcpu_nested_if(vcpu);
	struct vgic_v3_cpu_if *s_cpu_if = vcpu_shadow_if(vcpu);
	int nr_lr = kvm_vgic_global_state.nr_lr;
	int lr;

	for (lr = 0; lr < nr_lr; lr++) {
		s_cpu_if->vgic_lr[lr] &= ~ICH_LR_PHYS_ID_MASK;
		s_cpu_if->vgic_lr[lr] |= cpu_if->vgic_lr[lr] &
				ICH_LR_PHYS_ID_MASK;
	}
}

void vgic_v3_setup_shadow_state(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;
	struct vgic_v3_cpu_if *cpu_if;

	if (!nested_virt_in_use(vcpu)) {
		vgic_cpu->hw_v3_cpu_if = &vgic_cpu->vgic_v3;
		return;
	}

	if (vcpu_el2_imo_is_set(vcpu) && !vcpu_mode_el2(vcpu)) {
		vgic_cpu->shadow_vgic_v3 = vgic_cpu->nested_vgic_v3;
		vgic_v3_create_shadow_lr(vcpu);
		cpu_if = vcpu_shadow_if(vcpu);
	} else {
		cpu_if = &vgic_cpu->vgic_v3;
	}

	vgic_cpu->hw_v3_cpu_if = cpu_if;
}

void vgic_v3_restore_shadow_state(struct kvm_vcpu *vcpu)
{
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;

	if (!nested_virt_in_use(vcpu))
		return;

	/* Not using shadow state: Nothing to do... */
	if (vgic_cpu->hw_v3_cpu_if == &vgic_cpu->vgic_v3)
		return;

	/*
	 * Translate the shadow state HW fields back to the virtual ones
	 * before copying the shadow struct back to the nested one.
	 */
	vgic_v3_restore_shadow_lr(vcpu);
	vgic_cpu->nested_vgic_v3 = vgic_cpu->shadow_vgic_v3;
}

static inline bool lr_triggers_eoi(u64 lr)
{
	return !(lr & (ICH_LR_STATE | ICH_LR_HW)) && (lr & ICH_LR_EOI);
}

static unsigned long get_eisr(struct kvm_vcpu *vcpu)
{
	struct vgic_v3_cpu_if *cpu_if = vcpu_nested_if(vcpu);
	int nr_lr = min(kvm_vgic_global_state.nr_lr, 16);
	u64 reg = 0;
	int i;

	for (i = 0; i < nr_lr; i++) {
		if (lr_triggers_eoi(cpu_if->vgic_lr[i]))
			reg |= BIT(i);
	}

	return reg;
}

static u64 get_elrsr(struct kvm_vcpu *vcpu)
{
	struct vgic_v2_cpu_if *cpu_if = vcpu_nested_if(vcpu);
	int nr_lr = min(kvm_vgic_global_state.nr_lr, 16);
	u64 reg = 0;
	int i;

	for (i = 0; i < nr_lr; i++) {
		if (!(cpu_if->vgic_lr[i] & ICH_LR_STATE))
			reg |= BIT(i);
	}

	return reg;
}

static unsigned long vgic_mmio_read_v3_misr(struct kvm_vcpu *vcpu)
{
	struct vgic_v3_cpu_if *cpu_if = vcpu_nested_if(vcpu);
	int nr_lr = kvm_vgic_global_state.nr_lr;
	u32 reg = 0;

	if (get_eisr(vcpu))
		reg |= ICH_MISR_EOI;

	if (cpu_if->vgic_hcr & ICH_HCR_UIE) {
		u64 elrsr = get_elrsr(vcpu);
		int used_lrs;

		used_lrs = nr_lr - hweight64(elrsr);
		if (used_lrs <= 1)
			reg |= ICH_MISR_U;
	}

	/* TODO: Support remaining bits in this register */
	return reg;
}

void vgic_v3_handle_nested_maint_irq(struct kvm_vcpu *vcpu)
{
	struct vgic_v3_cpu_if *cpu_if = vcpu_nested_if(vcpu);

	if (!nested_virt_in_use(vcpu))
		return;

	/*
	 * If we exit a nested VM with a pending maintenance interrupt from the
	 * GIC, then we need to forward this to the guest hypervisor so that it
	 * can re-sync the appropriate LRs and sample level triggered interrupts
	 * again.
	 */
	if (vcpu_el2_imo_is_set(vcpu) && !vcpu_mode_el2(vcpu) &&
	    (cpu_if->vgic_hcr & ICH_HCR_EN) && vgic_mmio_read_v3_misr(vcpu))
		kvm_inject_nested_irq(vcpu);
}

void vgic_v3_init_nested(struct kvm_vcpu *vcpu)
{
	struct vgic_v3_cpu_if *vgic_v3 = vcpu_nested_if(vcpu);
	struct vgic_cpu *vgic_cpu = &vcpu->arch.vgic_cpu;

	if (!nested_virt_in_use(vcpu)) {
		pr_err("%s nsted gicv V3 not supported !!!!!!!!!!\n", __func__);
		vgic_cpu->hw_v3_cpu_if = &vgic_cpu->vgic_v3;
		return;
	}

	/*
	 * By forcing VMCR to zero, the GIC will restore the binary
	 * points to their reset values. Anything else resets to zero
	 * anyway.
	 */
	vgic_v3->vgic_vmcr = 0;
	vgic_v3->vgic_elrsr = ~0;

	/*
	 * If we are emulating a GICv3, we do it in an non-GICv2-compatible
	 * way, so we force SRE to 1 to demonstrate this to the guest.
	 * Also, we don't support any form of IRQ/FIQ bypass.
	 * This goes with the spec allowing the value to be RAO/WI.
	 */
	vgic_v3->vgic_sre = (ICC_SRE_EL2_DIB |
			     ICC_SRE_EL2_DFB |
			     ICC_SRE_EL2_SRE |
			     ICC_SRE_EL2_ENABLE);

	/* Get the show on the road... */
	vgic_v3->vgic_hcr = ICH_HCR_EN;

	vgic_v3_setup_shadow_state(vcpu);
}
