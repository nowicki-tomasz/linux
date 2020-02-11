/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __ARM64_KVM_NESTED_H
#define __ARM64_KVM_NESTED_H

#include <linux/kvm_host.h>

static inline bool nested_virt_in_use(const struct kvm_vcpu *vcpu)
{
	return cpus_have_const_cap(ARM64_HAS_NESTED_VIRT) &&
		test_bit(KVM_ARM_VCPU_HAS_EL2, vcpu->arch.features);
}

int handle_wfx_nested(struct kvm_vcpu *vcpu, bool is_wfe);
extern bool __forward_traps(struct kvm_vcpu *vcpu, unsigned int reg,
			    u64 control_bit);
extern bool forward_traps(struct kvm_vcpu *vcpu, u64 control_bit);
extern bool forward_nv_traps(struct kvm_vcpu *vcpu);

#endif /* __ARM64_KVM_NESTED_H */
