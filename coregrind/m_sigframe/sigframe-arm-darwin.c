
/*--------------------------------------------------------------------*/
/*--- Create/destroy signal delivery frames.                       ---*/
/*---                                        sigframe-arm-darwin.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2000-2013 Nicholas Nethercote
      njn@valgrind.org
   Copyright (C) 2004-2013 Paul Mackerras
      paulus@samba.org
   Copyright (C) 2008-2013 Evan Geller
      gaze@bea.ms
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
#include "pub_core_libcsetjmp.h"    // to keep _threadstate.h happy
#include "pub_core_threadstate.h"
#include "pub_core_aspacemgr.h"
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcprint.h"
#include "pub_core_machine.h"
#include "pub_core_options.h"
#include "pub_core_sigframe.h"
#include "pub_core_signals.h"
#include "pub_core_tooliface.h"
#include "pub_core_trampoline.h"
#include "pub_core_transtab.h"      // VG_(discard_translations)


/* This uses the hack of dumping the vex guest state along with both
   shadows in the frame, and restoring it afterwards from there,
   rather than pulling it out of the ucontext.  That means that signal
   handlers which modify the ucontext and then return, expecting their
   modifications to take effect, will have those modifications
   ignored.  This could be fixed properly with an hour or so more
   effort. */


struct vg_sig_private {
   UInt magicPI;
   UInt sigNo_private;
   //VexGuestARMState vex;
   VexGuestARMState vex_shadow1;
   VexGuestARMState vex_shadow2;
};

struct sigframe {
   vki_siginfo_t info;
   struct vki_ucontext uc;
   struct __darwin_mcontext32 mctxt;
   struct vg_sig_private vp;
};

static Bool __on_sig_stack ( ThreadState *tst, Addr sp )
{
   return (tst->altstack.ss_size == 0 ? False : (sp - (Addr)tst->altstack.ss_sp < (Addr)tst->altstack.ss_size));
}

static Bool extend ( ThreadState *tst, Addr addr, SizeT size, Bool isAltStk )
{
   ThreadId        tid = tst->tid;
   NSegment const* stackseg = NULL;

   // Do not extend it if currently is using the altstack
   if (!isAltStk) {
      if (VG_(extend_stack)(addr, tst->client_stack_szB)) {
         stackseg = VG_(am_find_nsegment)(addr);
      }
   }
   else {
      stackseg = VG_(am_find_nsegment)(addr);
   }
         
   if (0 && stackseg) {
       VG_(printf)("frame=%#lx seg=%#lx-%#lx\n",
              addr, stackseg->start, stackseg->end);}

   if (stackseg == NULL || !stackseg->hasR || !stackseg->hasW) {
      VG_(message)(
         Vg_UserMsg,
         "Can't extend stack to %#lx during signal delivery for thread %d:",
         addr, tid);
      if (stackseg == NULL)
         VG_(message)(Vg_UserMsg, "  no stack segment");
      else
         VG_(message)(Vg_UserMsg, "  too small or bad protection modes");

      /* set SIGSEGV to default handler */
      VG_(set_default_handler)(VKI_SIGSEGV);
      VG_(synth_fault_mapping)(tid, addr);

      /* The whole process should be about to die, since the default
    action of SIGSEGV to kill the whole process. */
      return False;
   }

   /* For tracking memory events, indicate the entire frame has been
      allocated. */
   VG_TRACK( new_mem_stack_signal, addr - VG_STACK_REDZONE_SZB,
             size + VG_STACK_REDZONE_SZB, tid );

   return True;
}

static void synth_ucontext( ThreadId tid, struct sigframe *frame, 
               const vki_siginfo_t *si, const struct vki_ucontext *siguc, 
               UInt flags, const vki_sigset_t *set, Addr sp){

   struct vki_ucontext *uc = &frame->uc;
   ThreadState *tst = VG_(get_ThreadState)(tid);

   VG_(memset)(uc, 0, sizeof(*uc));
   VG_(memset)(&frame->mctxt, 0, sizeof(struct __darwin_mcontext32));

   uc->uc_onstack = flags & VKI_SA_ONSTACK;
   uc->uc_link = 0;
   uc->uc_sigmask = *((sigset_t *)set);
   if ((flags & VKI_SA_ONSTACK) && (__on_sig_stack(tst, sp))) {
      uc->uc_stack = tst->altstack;
   }
   else {
      uc->uc_stack.ss_sp = (void *)sp;
      uc->uc_stack.ss_size = 0;
   }
   uc->uc_mcsize = sizeof(struct __darwin_mcontext32);
   struct __darwin_mcontext32 *sc = uc->uc_mcontext = &frame->mctxt;

   // General Registers (i.e. ss)
#  define SCSS2(reg,REG)  sc->__ss.reg = tst->arch.vex.guest_##REG
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
   sc->__ss.__cpsr = LibVEX_GuestARM_get_cpsr(&(tst->arch.vex));
#  undef SCSS2
   
   // FP Regsiters (i.e. fs)
#  define SCFS2(reg,REG)  *(ULong *)(&sc->__fs.reg) = tst->arch.vex.guest_##REG
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
   sc->__fs.__fpscr = tst->arch.vex.guest_FPSCR;
#  undef SCFS2

   // Exception state (i.e. es)
   if (siguc) {
      sc->__es.__exception = siguc->uc_mcontext->__es.__exception;
      sc->__es.__fsr = siguc->uc_mcontext->__es.__exception;
   }
   else {
      sc->__es.__exception = 0;
      sc->__es.__fsr = 0;
   }
   sc->__es.__far = (UInt)si->si_addr;
}


static void build_sigframe(ThreadState *tst,
            struct sigframe *frame,
            const vki_siginfo_t *siginfo,
            const struct vki_ucontext *siguc,
            UInt flags, const vki_sigset_t *mask,
            Addr sp){

   Int  sigNo = siginfo->si_signo;
   struct vg_sig_private *priv = &frame->vp;

   VG_TRACK( pre_mem_write, Vg_CoreSignal, tst->tid, "signal handler ucontext",
         (Addr)(&frame->uc), offsetof(struct sigframe, vp) - offsetof(struct sigframe, uc));

   synth_ucontext(tst->tid, frame, siginfo, siguc, flags, mask, sp);

   VG_TRACK( post_mem_write, Vg_CoreSignal, tst->tid,
         (Addr)(&frame->uc), offsetof(struct sigframe, vp) - offsetof(struct sigframe, uc));

   priv->magicPI = 0x31415927;
   priv->sigNo_private = sigNo;
   //priv->vex         = tst->arch.vex;
   priv->vex_shadow1 = tst->arch.vex_shadow1;
   priv->vex_shadow2 = tst->arch.vex_shadow2;

}



/* EXPORTED */
void VG_(sigframe_create)( ThreadId tid, 
                           Addr sp_top_of_frame,
                           const vki_siginfo_t *siginfo,
                           const struct vki_ucontext *siguc,
                           void *handler, 
                           UInt flags,
                           const vki_sigset_t *mask,
                           void *restorer )
{
   Addr sp = sp_top_of_frame;
   ThreadState *tst;
   Int sigNo = siginfo->si_signo;
   Bool isAltStk = False;

   tst = VG_(get_ThreadState)(tid);

   sp -= sizeof(struct sigframe);
   sp = VG_ROUNDDN(sp, 16);
   
   isAltStk = ((flags & VKI_SA_ONSTACK) && (__on_sig_stack(tst, sp)));

   if(!extend(tst, sp, sizeof(struct sigframe), isAltStk))
      return;

   struct sigframe *sf = (struct sigframe *)sp;
   
   /* Track our writes to siginfo */
   VG_TRACK( pre_mem_write, Vg_CoreSignal, tst->tid,  /* VVVVV */
         "signal handler siginfo", (Addr)sf, 
         sizeof(vki_siginfo_t));

   VG_(memcpy)(&sf->info, siginfo, sizeof(vki_siginfo_t));

   if(sigNo == VKI_SIGILL && siginfo->si_code > 0) {
      sf->info.si_addr = (Addr *) (tst)->arch.vex.guest_R12; /* IP */
   }
   VG_TRACK( post_mem_write, Vg_CoreSignal, tst->tid, /* ^^^^^ */
         (Addr)sf, sizeof(vki_siginfo_t));

   build_sigframe(tst, sf, siginfo, siguc, flags, mask, sp);
   tst->arch.vex.guest_R1 = (Addr)&sf->info;
   tst->arch.vex.guest_R2 = (Addr)&sf->uc;

   VG_(set_SP)(tid, sp);
   VG_TRACK( post_reg_write, Vg_CoreSignal, tid, VG_O_STACK_PTR,
         sizeof(Addr));
   tst->arch.vex.guest_R0  = sigNo; 

   tst->arch.vex.guest_R14 = (Addr)&VG_(arm_darwin_SUBST_FOR_sigreturn);

   tst->arch.vex.guest_R15T = (Addr) handler; /* R15 == PC */
}


/*------------------------------------------------------------*/
/*--- Destroying signal frames                             ---*/
/*------------------------------------------------------------*/

/* EXPORTED */
void VG_(sigframe_destroy)( ThreadId tid, Bool isRT )
{
   ThreadState *tst;
   struct vg_sig_private *priv;
   Addr sp;
   struct __darwin_mcontext32 *sc;
   Int sigNo;

   vg_assert(VG_(is_valid_tid)(tid));
   tst = VG_(get_ThreadState)(tid);
   sp = tst->arch.vex.guest_R13;

   struct sigframe *frame = (struct sigframe *)sp;
   sc = frame->uc.uc_mcontext;
   priv = &frame->vp;
   vg_assert(priv->magicPI == 0x31415927);
   tst->sig_mask = *(vki_sigset_t *)(&(frame->uc.uc_sigmask));
   tst->tmp_sig_mask = tst->sig_mask;
   sigNo = priv->sigNo_private;

   // General Registers (i.e. ss)
#  define SCSS2(reg,REG)  tst->arch.vex.guest_##REG = sc->__ss.reg
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
   LibVEX_GuestARM_set_cpsr(sc->__ss.__cpsr, &(tst->arch.vex));
#  undef SCSS2
   
   // FP Regsiters (i.e. fs)
#  define SCFS2(reg,REG)  tst->arch.vex.guest_##REG = *(ULong *)(&sc->__fs.reg)
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
   tst->arch.vex.guest_FPSCR = sc->__fs.__fpscr;
#  undef SCFS2

   /* Uh, the next line makes all the REST() above pointless. */
   //tst->arch.vex         = priv->vex;

   tst->arch.vex_shadow1 = priv->vex_shadow1;
   tst->arch.vex_shadow2 = priv->vex_shadow2;

   VG_TRACK( die_mem_stack_signal, sp - VG_STACK_REDZONE_SZB,
             sizeof(struct sigframe) + VG_STACK_REDZONE_SZB );
             
   if (VG_(clo_trace_signals))
      VG_(message)(Vg_DebugMsg,
                   "sigframe_destroy (thread %d): "
                   "valid magic; PC=%#x\n",
                   tid, tst->arch.vex.guest_R15T);

   /* tell the tools */
   VG_TRACK( post_deliver_signal, tid, sigNo );
}

#endif // defined(VGP_arm_darwin)

/*--------------------------------------------------------------------*/
/*--- end                                    sigframe-arm-darwin.c ---*/
/*--------------------------------------------------------------------*/
