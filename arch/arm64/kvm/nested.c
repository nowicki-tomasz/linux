// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017 - Columbia University and Linaro Ltd.
 * Author: Jintack Lim <jintack.lim@linaro.org>
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

#include <linux/kvm.h>
#include <linux/kvm_host.h>

#include <asm/kvm_arm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_nested.h>
#include <asm/sysreg.h>

#include "sys_regs.h"

void kvm_init_nested(struct kvm *kvm)
{
	kvm->arch.nested_mmus = NULL;
	kvm->arch.nested_mmus_size = 0;
}

int kvm_vcpu_init_nested(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_s2_mmu *tmp;
	int num_mmus;
	int ret = -ENOMEM;

	if (!test_bit(KVM_ARM_VCPU_HAS_EL2, vcpu->arch.features))
		return 0;

	if (!cpus_have_const_cap(ARM64_HAS_NESTED_VIRT))
		return -EINVAL;

	mutex_lock(&kvm->lock);

	/*
	 * Let's treat memory allocation failures as benign: If we fail to
	 * allocate anything, return an error and keep the allocated array
	 * alive. Userspace may try to recover by intializing the vcpu
	 * again, and there is no reason to affect the whole VM for this.
	 */
	num_mmus = atomic_read(&kvm->online_vcpus) * 2;
	tmp = __krealloc(kvm->arch.nested_mmus,
			 num_mmus * sizeof(*kvm->arch.nested_mmus),
			 GFP_KERNEL | __GFP_ZERO);

	if (tmp) {
		if (tmp != kvm->arch.nested_mmus)
			kfree(kvm->arch.nested_mmus);

		tmp[num_mmus - 1].kvm = kvm;
		atomic_set(&tmp[num_mmus - 1].refcnt, 0);
		tmp[num_mmus - 2].kvm = kvm;
		atomic_set(&tmp[num_mmus - 2].refcnt, 0);

		if (kvm_alloc_stage2_pgd(&tmp[num_mmus - 1]) ||
		    kvm_alloc_stage2_pgd(&tmp[num_mmus - 2])) {
			kvm_free_stage2_pgd(&tmp[num_mmus - 1]);
			kvm_free_stage2_pgd(&tmp[num_mmus - 2]);
		} else {
			kvm->arch.nested_mmus_size = num_mmus;
			ret = 0;
		}

		kvm->arch.nested_mmus = tmp;
	}

	mutex_unlock(&kvm->lock);
	return ret;
}

struct s2_walk_info {
	unsigned int pgshift;
	unsigned int pgsize;
	unsigned int ps;
	unsigned int sl;
	unsigned int t0sz;
};

static unsigned int ps_to_output_size(unsigned int ps)
{
	switch (ps) {
	case 0: return 32;
	case 1: return 36;
	case 2: return 40;
	case 3: return 42;
	case 4: return 44;
	case 5:
	default:
		return 48;
	}
}

static unsigned int pa_max(void)
{
	 /* We always emulate a VM with maximum PA size of KVM_PHYS_SIZE. */
	return KVM_PHYS_SHIFT;
}

static int esr_s2_fault(struct kvm_vcpu *vcpu, int level, u32 fsc)
{
	u32 esr;

	esr = kvm_vcpu_get_hsr(vcpu) & ~ESR_ELx_FSC;
	esr |= fsc;
	esr |= level & 0x3;
	return esr;
}

static int check_base_s2_limits(struct kvm_vcpu *vcpu, struct s2_walk_info *wi,
				int level, int input_size, int stride)
{
	int start_size;

	/* Check translation limits */
	switch (wi->pgsize) {
	case SZ_64K:
		if (level == 0 || (level == 1 && pa_max() <= 42))
			return -EFAULT;
		break;
	case SZ_16K:
		if (level == 0 || (level == 1 && pa_max() <= 40))
			return -EFAULT;
		break;
	case SZ_4K:
		if (level < 0 || (level == 0 && pa_max() <= 42))
			return -EFAULT;
		break;
	}

	/* Check input size limits */
	if (input_size > pa_max() &&
	    (!vcpu_mode_is_32bit(vcpu) || input_size > 40))
		return -EFAULT;

	/* Check number of entries in starting level table */
	start_size = input_size - ((3 - level) * stride + wi->pgshift);
	if (start_size < 1 || start_size > stride + 4)
		return -EFAULT;

	return 0;
}

/* Check if output is within boundaries */
static int check_output_size(struct kvm_vcpu *vcpu, struct s2_walk_info *wi,
			     phys_addr_t output)
{
	unsigned int output_size = ps_to_output_size(wi->ps);

	if (output_size > pa_max())
		output_size = pa_max();

	if (output_size != 48 && (output & GENMASK_ULL(47, output_size)))
		return -1;

	return 0;
}

/*
 * This is essentially a C-version of the pseudo code from the ARM ARM
 * AArch64.TranslationTableWalk  function.  I strongly recommend looking at
 * that pseudocode in trying to understand this.
 *
 * Must be called with the kvm->srcy read lock held
 */
static int walk_nested_s2_pgd(struct kvm_vcpu *vcpu, phys_addr_t ipa,
			      struct s2_walk_info *wi, struct kvm_s2_trans *out)
{
	u64 vttbr = vcpu_read_sys_reg(vcpu, VTTBR_EL2);
	int first_block_level, level, stride, input_size, base_lower_bound;
	phys_addr_t base_addr;
	unsigned int addr_top, addr_bottom;
	u64 desc;  /* page table entry */
	int ret;
	phys_addr_t paddr;

	switch (wi->pgsize) {
	case SZ_64K:
	case SZ_16K:
		level = 3 - wi->sl;
		first_block_level = 2;
		break;
	case SZ_4K:
		level = 2 - wi->sl;
		first_block_level = 1;
		break;
	default:
		/* GCC is braindead */
		unreachable();
	}

	stride = wi->pgshift - 3;
	input_size = 64 - wi->t0sz;
	if (input_size > 48 || input_size < 25)
		return -EFAULT;

	ret = check_base_s2_limits(vcpu, wi, level, input_size, stride);
	if (WARN_ON(ret))
		return ret;

	if (check_output_size(vcpu, wi, vttbr)) {
		out->esr = esr_s2_fault(vcpu, level, ESR_ELx_FSC_ADDRSZ);
		return 1;
	}

	base_lower_bound = 3 + input_size - ((3 - level) * stride +
			   wi->pgshift);
	base_addr = vttbr & GENMASK_ULL(47, base_lower_bound);

	addr_top = input_size - 1;

	while (1) {
		phys_addr_t index;

		addr_bottom = (3 - level) * stride + wi->pgshift;
		index = (ipa & GENMASK_ULL(addr_top, addr_bottom))
			>> (addr_bottom - 3);

		paddr = base_addr | index;
		ret = kvm_read_guest(vcpu->kvm, paddr, &desc, sizeof(desc));
		if (ret < 0)
			return ret;

		/*
		 * Handle reversedescriptors if endianness differs between the
		 * host and the guest hypervisor.
		 */
		if (vcpu_read_sys_reg(vcpu, SCTLR_EL2) & SCTLR_EE)
			desc = be64_to_cpu(desc);
		else
			desc = le64_to_cpu(desc);

		/* Check for valid descriptor at this point */
		if (!(desc & 1) || ((desc & 3) == 1 && level == 3)) {
			out->esr = esr_s2_fault(vcpu, level, ESR_ELx_FSC_FAULT);
			return 1;
		}

		/* We're at the final level or block translation level */
		if ((desc & 3) == 1 || level == 3)
			break;

		if (check_output_size(vcpu, wi, desc)) {
			out->esr = esr_s2_fault(vcpu, level, ESR_ELx_FSC_ADDRSZ);
			return 1;
		}

		base_addr = desc & GENMASK_ULL(47, wi->pgshift);

		level += 1;
		addr_top = addr_bottom - 1;
	}

	if (level < first_block_level) {
		out->esr = esr_s2_fault(vcpu, level, ESR_ELx_FSC_FAULT);
		return 1;
	}

	/*
	 * We don't use the contiguous bit in the stage-2 ptes, so skip check
	 * for misprogramming of the contiguous bit.
	 */

	if (check_output_size(vcpu, wi, desc)) {
		out->esr = esr_s2_fault(vcpu, level, ESR_ELx_FSC_ADDRSZ);
		return 1;
	}

	if (!(desc & BIT(10))) {
		out->esr = esr_s2_fault(vcpu, level, ESR_ELx_FSC_ACCESS);
		return 1;
	}

	/* Calculate and return the result */
	paddr = (desc & GENMASK_ULL(47, addr_bottom)) |
		(ipa & GENMASK_ULL(addr_bottom - 1, 0));
	out->output = paddr;
	out->block_size = 1UL << ((3 - level) * stride + wi->pgshift);
	out->readable = desc & (0b01 << 6);
	out->writable = desc & (0b10 << 6);
	out->level = level;
	out->upper_attr = desc & GENMASK_ULL(63, 52);
	return 0;
}

int kvm_walk_nested_s2(struct kvm_vcpu *vcpu, phys_addr_t gipa,
		       struct kvm_s2_trans *result)
{
	u64 vtcr = vcpu_read_sys_reg(vcpu, VTCR_EL2);
	struct s2_walk_info wi;

	result->esr = 0;

	if (!nested_virt_in_use(vcpu))
		return 0;

	wi.t0sz = vtcr & TCR_EL2_T0SZ_MASK;

	switch (vtcr & VTCR_EL2_TG0_MASK) {
	case VTCR_EL2_TG0_4K:
		wi.pgshift = 12;	 break;
	case VTCR_EL2_TG0_16K:
		wi.pgshift = 14;	 break;
	case VTCR_EL2_TG0_64K:
	default:
		wi.pgshift = 16;	 break;
	}
	wi.pgsize = 1UL << wi.pgshift;
	wi.ps = (vtcr & VTCR_EL2_PS_MASK) >> VTCR_EL2_PS_SHIFT;
	wi.sl = (vtcr & VTCR_EL2_SL0_MASK) >> VTCR_EL2_SL0_SHIFT;

	return walk_nested_s2_pgd(vcpu, gipa, &wi, result);
}

/* Must be called with kvm->lock held */
struct kvm_s2_mmu *lookup_s2_mmu(struct kvm *kvm, u64 vttbr, u64 hcr)
{
	bool nested_stage2_enabled = hcr & HCR_VM;
	int i;

	/* Don't consider the CnP bit for the vttbr match */
	vttbr = vttbr & ~VTTBR_CNP_BIT;

	/*
	 * Two possibilities when looking up a S2 MMU context:
	 *
	 * - either S2 is enabled in the guest, and we need a context that
         *   is S2-enabled and matches the full VTTBR (VMID+BADDR), which
         *   makes it safe from a TLB conflict perspective (a broken guest
         *   won't be able to generate them),
	 *
	 * - or S2 is disabled, and we need a context that is S2-disabled
         *   and matches the VMID only, as all TLBs are tagged by VMID even
         *   if S2 translation is enabled.
	 */
	for (i = 0; i < kvm->arch.nested_mmus_size; i++) {
		struct kvm_s2_mmu *mmu = &kvm->arch.nested_mmus[i];

		if (!kvm_s2_mmu_valid(mmu))
			continue;

		if (nested_stage2_enabled &&
		    mmu->nested_stage2_enabled &&
		    vttbr == mmu->vttbr)
			return mmu;

		if (!nested_stage2_enabled &&
		    !mmu->nested_stage2_enabled &&
		    get_vmid(vttbr) == get_vmid(mmu->vttbr))
			return mmu;
	}
	return NULL;
}

static struct kvm_s2_mmu *get_s2_mmu_nested(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	u64 vttbr = vcpu_read_sys_reg(vcpu, VTTBR_EL2);
	u64 hcr= vcpu_read_sys_reg(vcpu, HCR_EL2);
	struct kvm_s2_mmu *s2_mmu;
	int i;

	s2_mmu = lookup_s2_mmu(kvm, vttbr, hcr);
	if (s2_mmu)
		goto out;

	/*
	 * Make sure we don't always search from the same point, or we
	 * will always reuse a potentially active context, leaving
	 * free contexts unused.
	 */
	for (i = kvm->arch.nested_mmus_next;
	     i < (kvm->arch.nested_mmus_size + kvm->arch.nested_mmus_next);
	     i++) {
		s2_mmu = &kvm->arch.nested_mmus[i % kvm->arch.nested_mmus_size];

		if (atomic_read(&s2_mmu->refcnt) == 0)
			break;
	}
	BUG_ON(atomic_read(&s2_mmu->refcnt)); /* We have struct MMUs to spare */

	/* Set the scene for the next search */
	kvm->arch.nested_mmus_next = (i + 1) % kvm->arch.nested_mmus_size;

	if (kvm_s2_mmu_valid(s2_mmu)) {
		/* Clear the old state */
		kvm_unmap_stage2_range(s2_mmu, 0, kvm_phys_size(kvm));
		if (s2_mmu->vmid.vmid_gen)
			kvm_call_hyp(__kvm_tlb_flush_vmid, s2_mmu);
	}

	/*
	 * The virtual VMID (modulo CnP) will be used as a key when matching
	 * an existing kvm_s2_mmu.
	 */
	s2_mmu->vttbr = vttbr & ~VTTBR_CNP_BIT;
	s2_mmu->nested_stage2_enabled = hcr & HCR_VM;

out:
	atomic_inc(&s2_mmu->refcnt);
	return s2_mmu;
}

void kvm_init_s2_mmu(struct kvm_s2_mmu *mmu)
{
	mmu->vttbr = 1;
	mmu->nested_stage2_enabled = false;
	atomic_set(&mmu->refcnt, 0);
}

void kvm_vcpu_load_hw_mmu(struct kvm_vcpu *vcpu)
{
	if (is_hyp_ctxt(vcpu)) {
		vcpu->arch.hw_mmu = &vcpu->kvm->arch.mmu;
	} else {
		spin_lock(&vcpu->kvm->mmu_lock);
		vcpu->arch.hw_mmu = get_s2_mmu_nested(vcpu);
		spin_unlock(&vcpu->kvm->mmu_lock);
	}
}

void kvm_vcpu_put_hw_mmu(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.hw_mmu != &vcpu->kvm->arch.mmu) {
		atomic_dec(&vcpu->arch.hw_mmu->refcnt);
		vcpu->arch.hw_mmu = NULL;
	}
}

/*
 * Returns non-zero if permission fault is handled by injecting it to the next
 * level hypervisor.
 */
int kvm_s2_handle_perm_fault(struct kvm_vcpu *vcpu, struct kvm_s2_trans *trans)
{
	unsigned long fault_status = kvm_vcpu_trap_get_fault_type(vcpu);
	bool forward_fault = false;

	trans->esr = 0;

	if (fault_status != FSC_PERM)
		return 0;

	if (kvm_vcpu_trap_is_iabt(vcpu)) {
		forward_fault = (trans->upper_attr & PTE_S2_XN);
	} else {
		bool write_fault = kvm_is_write_fault(vcpu);

		forward_fault = ((write_fault && !trans->writable) ||
				 (!write_fault && !trans->readable));
	}

	if (forward_fault) {
		trans->esr = esr_s2_fault(vcpu, trans->level, ESR_ELx_FSC_PERM);
		return 1;
	}

	return 0;
}

int kvm_inject_s2_fault(struct kvm_vcpu *vcpu, u64 esr_el2)
{
	vcpu_write_sys_reg(vcpu, vcpu->arch.fault.far_el2, FAR_EL2);
	vcpu_write_sys_reg(vcpu, vcpu->arch.fault.hpfar_el2, HPFAR_EL2);

	return kvm_inject_nested_sync(vcpu, esr_el2);
}

/*
 * Inject wfx to the virtual EL2 if this is not from the virtual EL2 and
 * the virtual HCR_EL2.TWX is set. Otherwise, let the host hypervisor
 * handle this.
 */
int handle_wfx_nested(struct kvm_vcpu *vcpu, bool is_wfe)
{
	u64 hcr_el2 = __vcpu_sys_reg(vcpu, HCR_EL2);

	if (vcpu_mode_el2(vcpu))
		return -EINVAL;

	if ((is_wfe && (hcr_el2 & HCR_TWE)) || (!is_wfe && (hcr_el2 & HCR_TWI)))
		return kvm_inject_nested_sync(vcpu, kvm_vcpu_get_hsr(vcpu));

	return -EINVAL;
}

void kvm_arch_flush_shadow_all(struct kvm *kvm)
{
	int i;

	for (i = 0; i < kvm->arch.nested_mmus_size; i++) {
		struct kvm_s2_mmu *mmu = &kvm->arch.nested_mmus[i];

		WARN_ON(atomic_read(&mmu->refcnt));

		if (!atomic_read(&mmu->refcnt))
			kvm_free_stage2_pgd(mmu);
	}
	kfree(kvm->arch.nested_mmus);
	kvm->arch.nested_mmus = NULL;
	kvm->arch.nested_mmus_size = 0;
	kvm_free_stage2_pgd(&kvm->arch.mmu);
}

#define FEATURE(x)	(GENMASK_ULL(x##_SHIFT + 3, x##_SHIFT))

/*
 * Our emulated CPU doesn't support all the possible features. For the
 * sake of simplicity (and probably mental sanity), wipe out a number
 * of feature bits we don't intend to support for the time being.
 * This list should get updated as new features get added to the NV
 * support, and new extension to the architecture.
 *
 * Revisit: Implement as a whitelist rather than a blacklist?
 */
void access_nested_id_reg(struct kvm_vcpu *v, struct sys_reg_params *p,
			  const struct sys_reg_desc *r)
{
	u32 id = sys_reg((u32)r->Op0, (u32)r->Op1,
			 (u32)r->CRn, (u32)r->CRm, (u32)r->Op2);
	u64 val, tmp;

	if (!nested_virt_in_use(v))
		return;

	val = p->regval;

	switch (id) {
	case SYS_ID_AA64DFR0_EL1:
		/* No SPE */
		val &= ~FEATURE(ID_AA64DFR0_PMSVER);
		/* Cap PMU to ARMv8.1 */
		tmp = FIELD_GET(FEATURE(ID_AA64DFR0_PMUVER), val);
		if (tmp > 0b0100) {
			val &= FEATURE(ID_AA64DFR0_PMUVER);
			val |= FIELD_PREP(FEATURE(ID_AA64DFR0_PMUVER), 0b0100);
		}
		/* No trace */
		val &= FEATURE(ID_AA64DFR0_TRACEVER);
		/* Cap Debug to ARMv8.1 */
		tmp = FIELD_GET(FEATURE(ID_AA64DFR0_DEBUGVER), val);
		if (tmp > 0b0111) {
			val &= FEATURE(ID_AA64DFR0_DEBUGVER);
			val |= FIELD_PREP(FEATURE(ID_AA64DFR0_DEBUGVER), 0b0111);
		}
		break;

	case SYS_ID_AA64ISAR1_EL1:
		/* No PtrAuth */
		val &= ~(FEATURE(ID_AA64ISAR1_APA) |
			 FEATURE(ID_AA64ISAR1_API) |
			 FEATURE(ID_AA64ISAR1_GPA) |
			 FEATURE(ID_AA64ISAR1_GPI));
		break;

	case SYS_ID_AA64MMFR0_EL1:
		/* Hide unsupported S2 page sizes */
		switch (PAGE_SIZE) {
		case SZ_64K:
			val &= ~FEATURE(ID_AA64MMFR0_TGRAN16_2);
			val |= FIELD_PREP(FEATURE(ID_AA64MMFR0_TGRAN16_2), 0b0001);
			/* Fall through */
		case SZ_16K:
			val &= ~FEATURE(ID_AA64MMFR0_TGRAN4_2);
			val |= FIELD_PREP(FEATURE(ID_AA64MMFR0_TGRAN4_2), 0b0001);
			/* fall through */
		case SZ_4K:
			/* Support everything */
			break;
		}
		/* Cap PARange to 40bits */
		tmp = FIELD_GET(FEATURE(ID_AA64MMFR0_PARANGE), val);
		if (tmp > 0b0010) {
			val &= ~FEATURE(ID_AA64MMFR0_PARANGE);
			val |= FIELD_PREP(FEATURE(ID_AA64MMFR0_PARANGE), 0b0010);
		}
		break;

	case SYS_ID_AA64MMFR1_EL1:
		/* No XNX */
		val &= ~FEATURE(ID_AA64MMFR1_XNX);
		/* No RAS */
		val &= ~FEATURE(ID_AA64MMFR1_SpecSEI);
		/* No Hierarchical Permission Disable */
		val &= ~FEATURE(ID_AA64MMFR1_HPD);
		/* No Hardward Access flags and Dirty Bit State update */
		val &= ~FEATURE(ID_AA64MMFR1_HADBS);
		break;

	case SYS_ID_AA64MMFR2_EL1:
		/* No ARMv8.2-EVT */
		val &= ~FEATURE(ID_AA64MMFR2_EVT);
		/* No ARMv8.4-TTRem */
		val &= ~FEATURE(ID_AA64MMFR2_BBM);
		/* No ARMv8.4-TTST */
		val &= ~FEATURE(ID_AA64MMFR2_ST);
		/* No ARMv8.3-CCIDX */
		val &= ~FEATURE(ID_AA64MMFR2_CCIDX);
		/* No ARMv8.2-LVA */
		val &= ~FEATURE(ID_AA64MMFR2_LVA);
		break;

	case SYS_ID_AA64PFR0_EL1:
		/* No AMU */
		val &= ~FEATURE(ID_AA64PFR0_AMU);
		/* No MPAM */
		val &= ~FEATURE(ID_AA64PFR0_MPAM);
		/* No Secure EL2 */
		val &= ~FEATURE(ID_AA64PFR0_SEL2);
		/* No RAS */
		val &= ~FEATURE(ID_AA64PFR0_RAS);
		/* No SVE */
		val &= ~FEATURE(ID_AA64PFR0_SVE);
		/* EL2 is AArch64 only */
		val &= ~FEATURE(ID_AA64PFR0_EL2);
		val |= FIELD_PREP(FEATURE(ID_AA64PFR0_EL2), 0b0001);
		break;

	case SYS_ID_AA64PFR1_EL1:
		/* No MTE */
		val &= ~FEATURE(ID_AA64PFR1_MTE);
		/* No BT */
		val &= ~FEATURE(ID_AA64PFR1_BT);
		break;
	}

	p->regval = val;
}
