
/*--------------------------------------------------------------------*/
/*--- Create/destroy signal delivery frames.                       ---*/
/*---                                        sigframe-arm-darwin.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2006-2013 OpenWorks Ltd
      info@open-works.co.uk
   Copyright (C) 2014 Zhui Deng
      dengd03@gmail.com

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License as
   published by the Free Software Foundation; either version 2 of the
   License, or (at your option) any later version.

   This program is distributed in the hope that it will be useful, but
   WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
   02111-1307, USA.

   The GNU General Public License is contained in the file COPYING.
*/

#if defined(VGP_arm_darwin)

#include "pub_core_basics.h"
#include "pub_core_vki.h"
#include "pub_core_vkiscnums.h"
#include "pub_core_threadstate.h"
#include "pub_core_aspacemgr.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcprint.h"
#include "pub_core_machine.h"
#include "pub_core_options.h"
#include "pub_core_signals.h"
#include "pub_core_tooliface.h"
#include "pub_core_trampoline.h"
#include "pub_core_sigframe.h"      /* self */
#include "priv_sigframe.h"


/* Originally copied from ppc32-aix5 code.
   Produce a frame with layout entirely of our own choosing.

   This module creates and removes signal frames for signal deliveries
   on arm-darwin.  The machine state is saved in a ucontext and retrieved
   from it later, so the handler can modify it and return.

   Frame should have a 16-aligned size, just in case that turns out to
   be important for Darwin.  (be conservative)
*/
struct hacky_sigframe {
   UChar            lower_guardzone[512];  // put nothing here
   VexGuestARMState vex;
   VexGuestARMState vex_shadow1;
   VexGuestARMState vex_shadow2;
   vki_siginfo_t    fake_siginfo;
   struct vki_ucontext fake_ucontext;
   UInt             magicPI;
   UInt             sigNo_private;
   vki_sigset_t     mask; // saved sigmask; restore when hdlr returns
   UInt             __pad[3];
   UChar            upper_guardzone[512]; // put nothing here
   // and don't zero it, since that might overwrite the client's
   // stack redzone, at least on archs which have one
};


/* Create a plausible-looking sigcontext from the thread's
   Vex guest state.
 */
static void synthesize_ucontext(ThreadState *tst,
				struct vki_ucontext *uc,
				const struct vki_ucontext *siguc)
{
   VG_(memset)(uc, 0, sizeof(*uc));

   if (siguc) uc->uc_sigmask = siguc->uc_sigmask;
   uc->uc_stack = tst->altstack;
   uc->uc_mcontext = &uc->__mcontext_data;
   
   // General Registers (i.e. ss)
#  define SCSS2(reg,REG)  uc->__mcontext_data.__ss.reg = tst->arch.vex.guest_##REG
   SCSS2(__r[0],R0);
   SCSS2(__r[1],R1);
   SCSS2(__r[2],R2);
   SCSS2(__r[3],R3);
   SCSS2(__r[4],R4);
   SCSS2(__r[5],R5);
   SCSS2(__r[6],R6);
   SCSS2(__r[7],R7);
   SCSS2(__r[8],R8);
   SCSS2(__r[9],R9);
   SCSS2(__r[10],R10);
   SCSS2(__r[11],R11);
   SCSS2(__r[12],R12);
   SCSS2(__sp,R13);
   SCSS2(__lr,R14);
   SCSS2(__pc,R15T);
   uc->__mcontext_data.__ss.__cpsr = LibVEX_GuestARM_get_cpsr(&(tst->arch.vex));
#  undef SCSS2
   
   // FP Regsiters (i.e. fs)
#  define SCFS2(reg,REG)  *(ULong *)(&(uc->__mcontext_data.__fs.reg)) = tst->arch.vex.guest_##REG
   SCFS2(__r[0],D0);
   SCFS2(__r[2],D1);
   SCFS2(__r[4],D2);
   SCFS2(__r[6],D3);
   SCFS2(__r[8],D4);
   SCFS2(__r[10],D5);
   SCFS2(__r[12],D6);
   SCFS2(__r[14],D7);
   SCFS2(__r[16],D8);
   SCFS2(__r[18],D9);
   SCFS2(__r[20],D10);
   SCFS2(__r[22],D11);
   SCFS2(__r[24],D12);
   SCFS2(__r[26],D13);
   SCFS2(__r[28],D14);
   SCFS2(__r[30],D15);
   SCFS2(__r[32],D16);
   SCFS2(__r[34],D17);
   SCFS2(__r[36],D18);
   SCFS2(__r[38],D19);
   SCFS2(__r[40],D20);
   SCFS2(__r[42],D21);
   SCFS2(__r[44],D22);
   SCFS2(__r[46],D23);
   SCFS2(__r[48],D24);
   SCFS2(__r[50],D25);
   SCFS2(__r[52],D26);
   SCFS2(__r[54],D27);
   SCFS2(__r[56],D28);
   SCFS2(__r[58],D29);
   SCFS2(__r[60],D30);
   SCFS2(__r[62],D31);
   uc->__mcontext_data.__fs.__fpscr = tst->arch.vex.guest_FPSCR;
#  undef SCFS2

   if (siguc)
      uc->__mcontext_data.__es = siguc->__mcontext_data.__es;
}

static void restore_from_ucontext(ThreadState *tst,
				  const struct vki_ucontext *uc)
{
   // General Registers (i.e. ss)
#  define SCSS2(reg,REG)  tst->arch.vex.guest_##REG = uc->__mcontext_data.__ss.reg
   SCSS2(__r[0],R0);
   SCSS2(__r[1],R1);
   SCSS2(__r[2],R2);
   SCSS2(__r[3],R3);
   SCSS2(__r[4],R4);
   SCSS2(__r[5],R5);
   SCSS2(__r[6],R6);
   SCSS2(__r[7],R7);
   SCSS2(__r[8],R8);
   SCSS2(__r[9],R9);
   SCSS2(__r[10],R10);
   SCSS2(__r[11],R11);
   SCSS2(__r[12],R12);
   SCSS2(__sp,R13);
   SCSS2(__lr,R14);
   SCSS2(__pc,R15T);
   LibVEX_GuestARM_set_cpsr(uc->__mcontext_data.__ss.__cpsr, &(tst->arch.vex));
#  undef SCSS2
   
   // FP Regsiters (i.e. fs)
#  define SCFS2(reg,REG)  tst->arch.vex.guest_##REG = *(ULong *)(&(uc->__mcontext_data.__fs.reg))
   SCFS2(__r[0],D0);
   SCFS2(__r[2],D1);
   SCFS2(__r[4],D2);
   SCFS2(__r[6],D3);
   SCFS2(__r[8],D4);
   SCFS2(__r[10],D5);
   SCFS2(__r[12],D6);
   SCFS2(__r[14],D7);
   SCFS2(__r[16],D8);
   SCFS2(__r[18],D9);
   SCFS2(__r[20],D10);
   SCFS2(__r[22],D11);
   SCFS2(__r[24],D12);
   SCFS2(__r[26],D13);
   SCFS2(__r[28],D14);
   SCFS2(__r[30],D15);
   SCFS2(__r[32],D16);
   SCFS2(__r[34],D17);
   SCFS2(__r[36],D18);
   SCFS2(__r[38],D19);
   SCFS2(__r[40],D20);
   SCFS2(__r[42],D21);
   SCFS2(__r[44],D22);
   SCFS2(__r[46],D23);
   SCFS2(__r[48],D24);
   SCFS2(__r[50],D25);
   SCFS2(__r[52],D26);
   SCFS2(__r[54],D27);
   SCFS2(__r[56],D28);
   SCFS2(__r[58],D29);
   SCFS2(__r[60],D30);
   SCFS2(__r[62],D31);
   tst->arch.vex.guest_FPSCR = uc->__mcontext_data.__fs.__fpscr;
#  undef SCFS2
}

/* Create a signal frame for thread 'tid'.  Make a 3-arg frame
   regardless of whether the client originally requested a 1-arg
   version (no SA_SIGINFO) or a 3-arg one (SA_SIGINFO) since in the
   former case, the x86 calling conventions will simply cause the
   extra 2 args to be ignored (inside the handler). */
void VG_(sigframe_create) ( ThreadId tid,
                            Addr sp_top_of_frame,
                            const vki_siginfo_t *siginfo,
                            const struct vki_ucontext *siguc,
                            void *handler,
                            UInt flags,
                            const vki_sigset_t *mask,
                            void *restorer )
{
   ThreadState* tst;
   Addr esp;
   struct hacky_sigframe* frame;
   Int sigNo = siginfo->si_signo;

   vg_assert(VG_IS_16_ALIGNED(sizeof(struct hacky_sigframe)));

   sp_top_of_frame &= ~0xf;
   esp = sp_top_of_frame - sizeof(struct hacky_sigframe);

   tst = VG_(get_ThreadState)(tid);
   if (! ML_(sf_maybe_extend_stack)(tst, esp, sp_top_of_frame - esp, flags))
      return;

   vg_assert(VG_IS_4_ALIGNED(esp));

   frame = (struct hacky_sigframe *) esp;

   /* clear it (very conservatively) */
   VG_(memset)(&frame->lower_guardzone, 0, sizeof frame->lower_guardzone);
   VG_(memset)(&frame->vex,      0, sizeof(VexGuestARMState));
   VG_(memset)(&frame->vex_shadow1, 0, sizeof(VexGuestARMState));
   VG_(memset)(&frame->vex_shadow2, 0, sizeof(VexGuestARMState));
   VG_(memset)(&frame->fake_siginfo,  0, sizeof(frame->fake_siginfo));
   VG_(memset)(&frame->fake_ucontext, 0, sizeof(frame->fake_ucontext));

   /* save stuff in frame */
   frame->vex           = tst->arch.vex;
   frame->vex_shadow1   = tst->arch.vex_shadow1;
   frame->vex_shadow2   = tst->arch.vex_shadow2;
   frame->sigNo_private = sigNo;
   frame->mask          = tst->sig_mask;
   frame->magicPI       = 0x31415927;

   /* Fill in the siginfo and ucontext.  */
   synthesize_ucontext(tst, &frame->fake_ucontext, siguc);
   frame->fake_siginfo = *siginfo;

   /* Set up stack pointer */
   VG_(set_SP)(tid, esp);
   VG_TRACK( post_reg_write, Vg_CoreSignal, tid, VG_O_STACK_PTR, sizeof(UInt));

   /* Set up program counter */
   VG_(set_IP)(tid, (UInt)handler);
   VG_TRACK( post_reg_write, Vg_CoreSignal, tid, VG_O_INSTR_PTR, sizeof(UInt));

   /* Set up RA and args for the frame */
   tst->arch.vex.guest_R14 = (UInt)&VG_(arm_darwin_SUBST_FOR_sigreturn);
   tst->arch.vex.guest_R0 = sigNo; 
   tst->arch.vex.guest_R1 = (UInt)&frame->fake_siginfo;
   tst->arch.vex.guest_R2 = (UInt)&frame->fake_ucontext;
   VG_TRACK( post_mem_write, Vg_CoreSignal, tid,
             (Addr)&frame->fake_siginfo, sizeof(frame->fake_siginfo));
   VG_TRACK( post_mem_write, Vg_CoreSignal, tid,
             (Addr)&frame->fake_ucontext, sizeof(frame->fake_ucontext));

   if (VG_(clo_trace_signals))
      VG_(message)(Vg_DebugMsg,
                   "sigframe_create (thread %d): "
                   "next EIP=%#lx, next ESP=%#lx\n",
                   tid, (Addr)handler, (Addr)frame );
}

/* Remove a signal frame from thread 'tid's stack, and restore the CPU
   state from it.  Note, isRT is irrelevant here. */
void VG_(sigframe_destroy)( ThreadId tid, Bool isRT )
{
   ThreadState *tst;
   Addr sp;
   Int sigNo;
   struct hacky_sigframe* frame;
 
   vg_assert(VG_(is_valid_tid)(tid));
   tst = VG_(get_ThreadState)(tid);

   /* Check that the stack frame looks valid */
   sp = VG_(get_SP)(tid);

   frame = (struct hacky_sigframe*)(sp);
   vg_assert(frame->magicPI == 0x31415927);
   vg_assert(VG_IS_16_ALIGNED((Addr)frame));

   /* restore the entire guest state, and shadows, from the
      frame.  Note, as per comments above, this is a kludge - should
      restore it from saved ucontext.  Oh well. */
   tst->arch.vex = frame->vex;
   tst->arch.vex_shadow1 = frame->vex_shadow1;
   tst->arch.vex_shadow2 = frame->vex_shadow2;
   restore_from_ucontext(tst, &frame->fake_ucontext);

   tst->sig_mask = frame->mask;
   tst->tmp_sig_mask = frame->mask;
   sigNo = frame->sigNo_private;

   if (VG_(clo_trace_signals))
      VG_(message)(Vg_DebugMsg,
                   "sigframe_destroy (thread %d): "
                   "valid magic; next IP=%#x\n",
                   tid, tst->arch.vex.guest_R15T);

   VG_TRACK( die_mem_stack_signal, 
             (Addr)frame - VG_STACK_REDZONE_SZB, 
             sizeof(struct hacky_sigframe) );

   /* tell the tools */
   VG_TRACK( post_deliver_signal, tid, sigNo );
}

#endif // defined(VGP_arm_darwin)

/*--------------------------------------------------------------------*/
/*--- end                                    sigframe-arm-darwin.c ---*/
/*--------------------------------------------------------------------*/
