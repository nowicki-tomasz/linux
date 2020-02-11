// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2012-2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <linux/compiler.h>
#include <linux/kvm_host.h>

#include <asm/kprobes.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_nested.h>

/*
 * Non-VHE: Both host and guest must save everything.
 *
 * VHE: Host and guest must save mdscr_el1 and sp_el0 (and the PC and pstate,
 * which are handled as part of the el2 return state) on every switch.
 * tpidr_el0 and tpidrro_el0 only need to be switched when going
 * to host userspace or a different VCPU.  EL1 registers only need to be
 * switched when potentially going to run a different VCPU.  The latter two
 * classes are handled as part of kvm_arch_vcpu_load and kvm_arch_vcpu_put.
 */

static void __hyp_text __sysreg_save_common_state(struct kvm_cpu_context *ctxt)
{
	ctxt_sys_reg(ctxt, MDSCR_EL1)	= read_sysreg(mdscr_el1);

	/*
	 * The host arm64 Linux uses sp_el0 to point to 'current' and it must
	 * therefore be saved/restored on every entry/exit to/from the guest.
	 */
	ctxt->regs.sp			= read_sysreg(sp_el0);
}

static void __hyp_text __sysreg_save_user_state(struct kvm_cpu_context *ctxt)
{
	ctxt_sys_reg(ctxt, TPIDR_EL0)	= read_sysreg(tpidr_el0);
	ctxt_sys_reg(ctxt, TPIDRRO_EL0)	= read_sysreg(tpidrro_el0);
}

static void __hyp_text __sysreg_save_vel1_state(struct kvm_cpu_context *ctxt)
{
	ctxt_sys_reg(ctxt, SCTLR_EL1)	= read_sysreg_el1(SYS_SCTLR);
	ctxt_sys_reg(ctxt, CPACR_EL1)	= read_sysreg_el1(SYS_CPACR);
	ctxt_sys_reg(ctxt, TTBR0_EL1)	= read_sysreg_el1(SYS_TTBR0);
	ctxt_sys_reg(ctxt, TTBR1_EL1)	= read_sysreg_el1(SYS_TTBR1);
	ctxt_sys_reg(ctxt, TCR_EL1)	= read_sysreg_el1(SYS_TCR);
	ctxt_sys_reg(ctxt, ESR_EL1)	= read_sysreg_el1(SYS_ESR);
	ctxt_sys_reg(ctxt, AFSR0_EL1)	= read_sysreg_el1(SYS_AFSR0);
	ctxt_sys_reg(ctxt, AFSR1_EL1)	= read_sysreg_el1(SYS_AFSR1);
	ctxt_sys_reg(ctxt, FAR_EL1)	= read_sysreg_el1(SYS_FAR);
	ctxt_sys_reg(ctxt, MAIR_EL1)	= read_sysreg_el1(SYS_MAIR);
	ctxt_sys_reg(ctxt, VBAR_EL1)	= read_sysreg_el1(SYS_VBAR);
	ctxt_sys_reg(ctxt, CONTEXTIDR_EL1) = read_sysreg_el1(SYS_CONTEXTIDR);
	ctxt_sys_reg(ctxt, AMAIR_EL1)	= read_sysreg_el1(SYS_AMAIR);
	ctxt_sys_reg(ctxt, CNTKCTL_EL1)	= read_sysreg_el1(SYS_CNTKCTL);

	ctxt_sys_reg(ctxt, SP_EL1)	= read_sysreg(sp_el1);
	ctxt_sys_reg(ctxt, ELR_EL1)	= read_sysreg_el1(SYS_ELR);
	ctxt->spsr_el1			= read_sysreg_el1(SYS_SPSR);
}

static void __sysreg_save_vel2_state(struct kvm_cpu_context *ctxt)
{
	ctxt_sys_reg(ctxt, ESR_EL2)	= read_sysreg_el1(SYS_ESR);
	ctxt_sys_reg(ctxt, AFSR0_EL2)	= read_sysreg_el1(SYS_AFSR0);
	ctxt_sys_reg(ctxt, AFSR1_EL2)	= read_sysreg_el1(SYS_AFSR1);
	ctxt_sys_reg(ctxt, FAR_EL2)	= read_sysreg_el1(SYS_FAR);
	ctxt_sys_reg(ctxt, MAIR_EL2)	= read_sysreg_el1(SYS_MAIR);
	ctxt_sys_reg(ctxt, VBAR_EL2)	= read_sysreg_el1(SYS_VBAR);
	ctxt_sys_reg(ctxt, CONTEXTIDR_EL2) = read_sysreg_el1(SYS_CONTEXTIDR);
	ctxt_sys_reg(ctxt, AMAIR_EL2)	= read_sysreg_el1(SYS_AMAIR);

	/*
	 * In VHE mode those registers are compatible between EL1 and EL2,
	 * and the guest uses the _EL1 versions on the CPU naturally.
	 * So we save them into their _EL2 versions here.
	 * For nVHE mode we trap accesses to those registers, so our
	 * _EL2 copy in sys_regs[] is always up-to-date and we don't need
	 * to save anything here.
	 */
	if (__vcpu_el2_e2h_is_set(ctxt)) {
		ctxt_sys_reg(ctxt, SCTLR_EL2)	= read_sysreg_el1(SYS_SCTLR);
		ctxt_sys_reg(ctxt, CPTR_EL2)	= read_sysreg_el1(SYS_CPACR);
		ctxt_sys_reg(ctxt, TTBR0_EL2)	= read_sysreg_el1(SYS_TTBR0);
		ctxt_sys_reg(ctxt, TTBR1_EL2)	= read_sysreg_el1(SYS_TTBR1);
		ctxt_sys_reg(ctxt, TCR_EL2)	= read_sysreg_el1(SYS_TCR);
		ctxt_sys_reg(ctxt, CNTHCTL_EL2)	= read_sysreg_el1(SYS_CNTKCTL);
	}

	ctxt_sys_reg(ctxt, SP_EL2)	= read_sysreg(sp_el1);
	ctxt_sys_reg(ctxt, ELR_EL2)	= read_sysreg_el1(SYS_ELR);
	ctxt_sys_reg(ctxt, SPSR_EL2)	= __fixup_spsr_el2_read(ctxt, read_sysreg_el1(SYS_SPSR));
}

static void __hyp_text __sysreg_save_el1_state(struct kvm_cpu_context *ctxt)
{
	ctxt_sys_reg(ctxt, CSSELR_EL1)	= read_sysreg(csselr_el1);
	ctxt_sys_reg(ctxt, ACTLR_EL1)	= read_sysreg(actlr_el1);
	ctxt_sys_reg(ctxt, PAR_EL1)	= read_sysreg(par_el1);
	ctxt_sys_reg(ctxt, TPIDR_EL1)	= read_sysreg(tpidr_el1);

	if (unlikely(__is_hyp_ctxt(ctxt)))
		__sysreg_save_vel2_state(ctxt);
	else
		__sysreg_save_vel1_state(ctxt);
}

static u64 __hyp_text from_hw_pstate(const struct kvm_cpu_context *ctxt)
{
	u64 reg = read_sysreg_el2(SYS_SPSR);

	if (__is_hyp_ctxt(ctxt)) {
		u64 mode = reg & (PSR_MODE_MASK | PSR_MODE32_BIT);

		switch (mode) {
		case PSR_MODE_EL1t:
			mode = PSR_MODE_EL2t;
			break;
		case PSR_MODE_EL1h:
			mode = PSR_MODE_EL2h;
			break;
		}

		return (reg & ~(PSR_MODE_MASK | PSR_MODE32_BIT)) | mode;
	}

	return reg;
}

static void __hyp_text __sysreg_save_el2_return_state(struct kvm_cpu_context *ctxt)
{
	ctxt->regs.pc			= read_sysreg_el2(SYS_ELR);
	ctxt->regs.pstate		= from_hw_pstate(ctxt);

	if (cpus_have_const_cap(ARM64_HAS_RAS_EXTN))
		ctxt_sys_reg(ctxt, DISR_EL1) = read_sysreg_s(SYS_VDISR_EL2);
}

void __hyp_text __sysreg_save_state_nvhe(struct kvm_cpu_context *ctxt)
{
	__sysreg_save_el1_state(ctxt);
	__sysreg_save_common_state(ctxt);
	__sysreg_save_user_state(ctxt);
	__sysreg_save_el2_return_state(ctxt);
}

void sysreg_save_host_state_vhe(struct kvm_cpu_context *ctxt)
{
	__sysreg_save_common_state(ctxt);
}
NOKPROBE_SYMBOL(sysreg_save_host_state_vhe);

void sysreg_save_guest_state_vhe(struct kvm_cpu_context *ctxt)
{
	__sysreg_save_common_state(ctxt);
	__sysreg_save_el2_return_state(ctxt);
}
NOKPROBE_SYMBOL(sysreg_save_guest_state_vhe);

static void __hyp_text __sysreg_restore_common_state(struct kvm_cpu_context *ctxt)
{
	write_sysreg(ctxt_sys_reg(ctxt, MDSCR_EL1),  mdscr_el1);

	/*
	 * The host arm64 Linux uses sp_el0 to point to 'current' and it must
	 * therefore be saved/restored on every entry/exit to/from the guest.
	 */
	write_sysreg(ctxt->regs.sp,		  sp_el0);
}

static void __hyp_text __sysreg_restore_user_state(struct kvm_cpu_context *ctxt)
{
	write_sysreg(ctxt_sys_reg(ctxt, TPIDR_EL0),	tpidr_el0);
	write_sysreg(ctxt_sys_reg(ctxt, TPIDRRO_EL0),	tpidrro_el0);
}

static void __sysreg_restore_vel2_state(struct kvm_cpu_context *ctxt)
{
	u64 val;

	write_sysreg(read_cpuid_id(),			vpidr_el2);
	write_sysreg(ctxt_sys_reg(ctxt, MPIDR_EL1),	vmpidr_el2);
	write_sysreg_el1(ctxt_sys_reg(ctxt, MAIR_EL2),	SYS_MAIR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, VBAR_EL2),	SYS_VBAR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, CONTEXTIDR_EL2),SYS_CONTEXTIDR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, AMAIR_EL2),	SYS_AMAIR);

	if (__vcpu_el2_e2h_is_set(ctxt)) {
		/*
		 * In VHE mode those registers are compatible between
		 * EL1 and EL2.
		 */
		write_sysreg_el1(ctxt_sys_reg(ctxt, SCTLR_EL2),	SYS_SCTLR);
		write_sysreg_el1(ctxt_sys_reg(ctxt, CPTR_EL2),	SYS_CPACR);
		write_sysreg_el1(ctxt_sys_reg(ctxt, TTBR0_EL2),	SYS_TTBR0);
		write_sysreg_el1(ctxt_sys_reg(ctxt, TTBR1_EL2),	SYS_TTBR1);
		write_sysreg_el1(ctxt_sys_reg(ctxt, TCR_EL2),	SYS_TCR);
		write_sysreg_el1(ctxt_sys_reg(ctxt, CNTHCTL_EL2), SYS_CNTKCTL);
	} else {
		write_sysreg_el1(translate_sctlr(ctxt_sys_reg(ctxt, SCTLR_EL2)),
				 SYS_SCTLR);
		write_sysreg_el1(translate_cptr(ctxt_sys_reg(ctxt, CPTR_EL2)),
				 SYS_CPACR);
		write_sysreg_el1(translate_ttbr0(ctxt_sys_reg(ctxt, TTBR0_EL2)),
				 SYS_TTBR0);
		write_sysreg_el1(translate_tcr(ctxt_sys_reg(ctxt, TCR_EL2)),
				 SYS_TCR);
		write_sysreg_el1(translate_cnthctl(ctxt_sys_reg(ctxt, CNTHCTL_EL2)),
				 SYS_CNTKCTL);
	}

	/*
	 * These registers can be modified behind our back by a fault
	 * taken inside vEL2. Save them, always.
	 */
	write_sysreg_el1(ctxt_sys_reg(ctxt, ESR_EL2),	SYS_ESR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, AFSR0_EL2),	SYS_AFSR0);
	write_sysreg_el1(ctxt_sys_reg(ctxt, AFSR1_EL2),	SYS_AFSR1);
	write_sysreg_el1(ctxt_sys_reg(ctxt, FAR_EL2),	SYS_FAR);
	write_sysreg(ctxt_sys_reg(ctxt, SP_EL2),	sp_el1);
	write_sysreg_el1(ctxt_sys_reg(ctxt, ELR_EL2),	SYS_ELR);

	val = __fixup_spsr_el2_write(ctxt, ctxt_sys_reg(ctxt, SPSR_EL2));
	write_sysreg_el1(val,	SYS_SPSR);
}

static void __hyp_text __sysreg_restore_vel1_state(struct kvm_cpu_context *ctxt)
{
	u64 mpidr;

	if (has_vhe()) {
		struct kvm_vcpu *vcpu;

		/*
		 * We need to go from a context to a vcpu, but this is a
		 * complicated affair.
		 *
		 * On VHE, we should never be here with the host context as
		 * a parameter, so let's check and bail out if that's the
		 * case.
		 */
		if (WARN_ON_ONCE(ctxt->__hyp_running_vcpu))
			return;

		/*
		 * Now that we know for sure this is a guest context, we can
		 * extract the vcpu...
		 */
		vcpu = container_of(ctxt, struct kvm_vcpu, arch.ctxt);

		if (nested_virt_in_use(vcpu)) {
			/*
			 * Only set VPIDR_EL2 for nested VMs, as this is the
			 * only time it changes. We'll restore the MIDR_EL1
			 * view on put.
			 */
			write_sysreg(ctxt_sys_reg(ctxt, VPIDR_EL2),	vpidr_el2);

			/*
			 * As we're restoring a nested guest, set the value
			 * provided by the guest hypervisor.
			 */
			mpidr = ctxt_sys_reg(ctxt, VMPIDR_EL2);
		} else {
			mpidr = ctxt_sys_reg(ctxt, MPIDR_EL1);
		}
	} else {
		mpidr = ctxt_sys_reg(ctxt, MPIDR_EL1);
	}

	write_sysreg(mpidr,				vmpidr_el2);
	write_sysreg_el1(ctxt_sys_reg(ctxt, SCTLR_EL1),	SYS_SCTLR);

	if (!cpus_have_const_cap(ARM64_WORKAROUND_SPECULATIVE_AT_NVHE)) {
		write_sysreg_el1(ctxt_sys_reg(ctxt, SCTLR_EL1),	SYS_SCTLR);
		write_sysreg_el1(ctxt_sys_reg(ctxt, TCR_EL1),	SYS_TCR);
	} else	if (!ctxt->__hyp_running_vcpu) {
		/*
		 * Must only be done for guest registers, hence the context
		 * test. We're coming from the host, so SCTLR.M is already
		 * set. Pairs with __activate_traps_nvhe().
		 */
		write_sysreg_el1((ctxt_sys_reg(ctxt, TCR_EL1) |
				  TCR_EPD1_MASK | TCR_EPD0_MASK),
				 SYS_TCR);
		isb();
	}

	write_sysreg(ctxt_sys_reg(ctxt, ACTLR_EL1),		actlr_el1);
	write_sysreg_el1(ctxt_sys_reg(ctxt, CPACR_EL1),	SYS_CPACR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, TTBR0_EL1),	SYS_TTBR0);
	write_sysreg_el1(ctxt_sys_reg(ctxt, TTBR1_EL1),	SYS_TTBR1);
	write_sysreg_el1(ctxt_sys_reg(ctxt, ESR_EL1),	SYS_ESR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, AFSR0_EL1),	SYS_AFSR0);
	write_sysreg_el1(ctxt_sys_reg(ctxt, AFSR1_EL1),	SYS_AFSR1);
	write_sysreg_el1(ctxt_sys_reg(ctxt, FAR_EL1),	SYS_FAR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, MAIR_EL1),	SYS_MAIR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, VBAR_EL1),	SYS_VBAR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, CONTEXTIDR_EL1),SYS_CONTEXTIDR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, AMAIR_EL1),	SYS_AMAIR);
	write_sysreg_el1(ctxt_sys_reg(ctxt, CNTKCTL_EL1),	SYS_CNTKCTL);
	write_sysreg(ctxt_sys_reg(ctxt, PAR_EL1),		par_el1);
	write_sysreg(ctxt_sys_reg(ctxt, TPIDR_EL1),		tpidr_el1);

	if (cpus_have_const_cap(ARM64_WORKAROUND_SPECULATIVE_AT_NVHE) &&
	    ctxt->__hyp_running_vcpu) {
		/*
		 * Must only be done for host registers, hence the context
		 * test. Pairs with __deactivate_traps_nvhe().
		 */
		isb();
		/*
		 * At this stage, and thanks to the above isb(), S2 is
		 * deconfigured and disabled. We can now restore the host's
		 * S1 configuration: SCTLR, and only then TCR.
		 */
		write_sysreg_el1(ctxt_sys_reg(ctxt, SCTLR_EL1),	SYS_SCTLR);
		isb();
		write_sysreg_el1(ctxt_sys_reg(ctxt, TCR_EL1),	SYS_TCR);
	}

	write_sysreg(ctxt_sys_reg(ctxt, SP_EL1),	sp_el1);
	write_sysreg_el1(ctxt_sys_reg(ctxt, ELR_EL1),	SYS_ELR);
	write_sysreg_el1(ctxt->spsr_el1,		SYS_SPSR);
}

static void __hyp_text __sysreg_restore_el1_state(struct kvm_cpu_context *ctxt)
{
	write_sysreg(ctxt_sys_reg(ctxt, CSSELR_EL1),	csselr_el1);
	write_sysreg(ctxt_sys_reg(ctxt, ACTLR_EL1),	actlr_el1);
	write_sysreg(ctxt_sys_reg(ctxt, PAR_EL1),	par_el1);
	write_sysreg(ctxt_sys_reg(ctxt, TPIDR_EL1),	tpidr_el1);

	if (__is_hyp_ctxt(ctxt))
		__sysreg_restore_vel2_state(ctxt);
	else
		__sysreg_restore_vel1_state(ctxt);
}

/* Read the VCPU state's PSTATE, but translate (v)EL2 to EL1. */
static u64 __hyp_text to_hw_pstate(const struct kvm_cpu_context *ctxt)
{
	u64 mode = ctxt->regs.pstate & (PSR_MODE_MASK | PSR_MODE32_BIT);

	switch (mode) {
	case PSR_MODE_EL2t:
		mode = PSR_MODE_EL1t;
		break;
	case PSR_MODE_EL2h:
		mode = PSR_MODE_EL1h;
		break;
	}

	return (ctxt->regs.pstate & ~(PSR_MODE_MASK | PSR_MODE32_BIT)) | mode;
}

static void __hyp_text
__sysreg_restore_el2_return_state(struct kvm_cpu_context *ctxt)
{
	u64 pstate = to_hw_pstate(ctxt);
	u64 mode = pstate & PSR_AA32_MODE_MASK;

	/*
	 * Safety check to ensure we're setting the CPU up to enter the guest
	 * in a less privileged mode.
	 *
	 * If we are attempting a return to EL2 or higher in AArch64 state,
	 * program SPSR_EL2 with M=EL2h and the IL bit set which ensures that
	 * we'll take an illegal exception state exception immediately after
	 * the ERET to the guest.  Attempts to return to AArch32 Hyp will
	 * result in an illegal exception return because EL2's execution state
	 * is determined by SCR_EL3.RW.
	 */
	if (!(mode & PSR_MODE32_BIT) && mode >= PSR_MODE_EL2t)
		pstate = PSR_MODE_EL2h | PSR_IL_BIT;

	write_sysreg_el2(ctxt->regs.pc,			SYS_ELR);
	write_sysreg_el2(pstate,			SYS_SPSR);

	if (cpus_have_const_cap(ARM64_HAS_RAS_EXTN))
		write_sysreg_s(ctxt_sys_reg(ctxt, DISR_EL1), SYS_VDISR_EL2);
}

void __hyp_text __sysreg_restore_state_nvhe(struct kvm_cpu_context *ctxt)
{
	__sysreg_restore_el1_state(ctxt);
	__sysreg_restore_common_state(ctxt);
	__sysreg_restore_user_state(ctxt);
	__sysreg_restore_el2_return_state(ctxt);
}

void sysreg_restore_host_state_vhe(struct kvm_cpu_context *ctxt)
{
	__sysreg_restore_common_state(ctxt);
}
NOKPROBE_SYMBOL(sysreg_restore_host_state_vhe);

void sysreg_restore_guest_state_vhe(struct kvm_cpu_context *ctxt)
{
	__sysreg_restore_common_state(ctxt);
	__sysreg_restore_el2_return_state(ctxt);
}
NOKPROBE_SYMBOL(sysreg_restore_guest_state_vhe);

void __hyp_text __sysreg32_save_state(struct kvm_vcpu *vcpu)
{
	if (!vcpu_el1_is_32bit(vcpu))
		return;

	vcpu->arch.ctxt.spsr_abt = read_sysreg(spsr_abt);
	vcpu->arch.ctxt.spsr_und = read_sysreg(spsr_und);
	vcpu->arch.ctxt.spsr_irq = read_sysreg(spsr_irq);
	vcpu->arch.ctxt.spsr_fiq = read_sysreg(spsr_fiq);

	__vcpu_sys_reg(vcpu, DACR32_EL2) = read_sysreg(dacr32_el2);
	__vcpu_sys_reg(vcpu, IFSR32_EL2) = read_sysreg(ifsr32_el2);

	if (has_vhe() || vcpu->arch.flags & KVM_ARM64_DEBUG_DIRTY)
		__vcpu_sys_reg(vcpu, DBGVCR32_EL2) = read_sysreg(dbgvcr32_el2);
}

void __hyp_text __sysreg32_restore_state(struct kvm_vcpu *vcpu)
{
	if (!vcpu_el1_is_32bit(vcpu))
		return;

	write_sysreg(vcpu->arch.ctxt.spsr_abt, spsr_abt);
	write_sysreg(vcpu->arch.ctxt.spsr_und, spsr_und);
	write_sysreg(vcpu->arch.ctxt.spsr_irq, spsr_irq);
	write_sysreg(vcpu->arch.ctxt.spsr_fiq, spsr_fiq);

	write_sysreg(__vcpu_sys_reg(vcpu, DACR32_EL2), dacr32_el2);
	write_sysreg(__vcpu_sys_reg(vcpu, IFSR32_EL2), ifsr32_el2);

	if (has_vhe() || vcpu->arch.flags & KVM_ARM64_DEBUG_DIRTY)
		write_sysreg(__vcpu_sys_reg(vcpu, DBGVCR32_EL2), dbgvcr32_el2);
}

/**
 * kvm_vcpu_load_sysregs - Load guest system registers to the physical CPU
 *
 * @vcpu: The VCPU pointer
 *
 * Load system registers that do not affect the host's execution, for
 * example EL1 system registers on a VHE system where the host kernel
 * runs at EL2.  This function is called from KVM's vcpu_load() function
 * and loading system register state early avoids having to load them on
 * every entry to the VM.
 */
void kvm_vcpu_load_sysregs(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *host_ctxt = vcpu->arch.host_cpu_context;
	struct kvm_cpu_context *guest_ctxt = &vcpu->arch.ctxt;

	if (!has_vhe())
		return;

	__sysreg_save_user_state(host_ctxt);

	/*
	 * Load guest EL1 and user state
	 *
	 * We must restore the 32-bit state before the sysregs, thanks
	 * to erratum #852523 (Cortex-A57) or #853709 (Cortex-A72).
	 */
	__sysreg32_restore_state(vcpu);
	__sysreg_restore_user_state(guest_ctxt);
	__sysreg_restore_el1_state(guest_ctxt);

	vcpu->arch.sysregs_loaded_on_cpu = true;

	activate_traps_vhe_load(vcpu);
}

/**
 * kvm_vcpu_put_sysregs - Restore host system registers to the physical CPU
 *
 * @vcpu: The VCPU pointer
 *
 * Save guest system registers that do not affect the host's execution, for
 * example EL1 system registers on a VHE system where the host kernel
 * runs at EL2.  This function is called from KVM's vcpu_put() function
 * and deferring saving system register state until we're no longer running the
 * VCPU avoids having to save them on every exit from the VM.
 */
void kvm_vcpu_put_sysregs(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *host_ctxt = vcpu->arch.host_cpu_context;
	struct kvm_cpu_context *guest_ctxt = &vcpu->arch.ctxt;

	if (!has_vhe())
		return;

	deactivate_traps_vhe_put();

	__sysreg_save_el1_state(guest_ctxt);
	__sysreg_save_user_state(guest_ctxt);
	__sysreg32_save_state(vcpu);

	/* Restore host user state */
	__sysreg_restore_user_state(host_ctxt);

	/*
	 * If leaving a nesting guest, restore MPIDR_EL1 default view. It is
	 * slightly ugly to do it here, but the alternative is to penalize
	 * all non-nesting guests by forcing this on every load. Instead, we
	 * choose to only penalize nesting VMs.
	 */
	if (nested_virt_in_use(vcpu))
		write_sysreg(read_cpuid_id(),	vpidr_el2);

	vcpu->arch.sysregs_loaded_on_cpu = false;
}

void __hyp_text __kvm_enable_ssbs(void)
{
	u64 tmp;

	asm volatile(
	"mrs	%0, sctlr_el2\n"
	"orr	%0, %0, %1\n"
	"msr	sctlr_el2, %0"
	: "=&r" (tmp) : "L" (SCTLR_ELx_DSSBS));
}
