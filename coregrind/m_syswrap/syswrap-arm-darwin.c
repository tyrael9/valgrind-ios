
/*--------------------------------------------------------------------*/
/*--- Darwin-specific syscalls, etc.          syswrap-arm-darwin.c ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2005-2013 Apple Inc.
      Greg Parker  gparker@apple.com
   Copyright (C) 2005-2013 Zhui Deng
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
#include "pub_core_libcsetjmp.h"   // to keep _threadstate.h happy
#include "pub_core_threadstate.h"
#include "pub_core_aspacemgr.h"
#include "pub_core_xarray.h"
#include "pub_core_clientstate.h"
#include "pub_core_debuglog.h"
#include "pub_core_debuginfo.h"    // VG_(di_notify_*)
#include "pub_core_transtab.h"     // VG_(discard_translations)
#include "pub_core_libcbase.h"
#include "pub_core_libcassert.h"
#include "pub_core_libcfile.h"
#include "pub_core_libcprint.h"
#include "pub_core_libcproc.h"
#include "pub_core_libcsignal.h"
#include "pub_core_machine.h"      // VG_(get_SP)
#include "pub_core_mallocfree.h"
#include "pub_core_options.h"
#include "pub_core_scheduler.h"
#include "pub_core_signals.h"
#include "pub_core_syscall.h"
#include "pub_core_syswrap.h"
#include "pub_core_tooliface.h"

#include "priv_types_n_macros.h"
#include "priv_syswrap-generic.h"   /* for decls of generic wrappers */
#include "priv_syswrap-darwin.h"    /* for decls of darwin-ish wrappers */
#include "priv_syswrap-main.h"


#include <mach/mach.h>

static void arm_thread_state32_from_vex(arm_thread_state_t *mach, 
                                        VexGuestARMState *vex)
{
    mach->__r[0] = vex->guest_R0;
    mach->__r[1] = vex->guest_R1;
    mach->__r[2] = vex->guest_R2;
    mach->__r[3] = vex->guest_R3;
    mach->__r[4] = vex->guest_R4;
    mach->__r[5] = vex->guest_R5;
    mach->__r[6] = vex->guest_R6;
    mach->__r[7] = vex->guest_R7;
    mach->__r[8] = vex->guest_R8;
    mach->__r[9] = vex->guest_R9;
    mach->__r[10] = vex->guest_R10;
    mach->__r[11] = vex->guest_R11;
    mach->__r[12] = vex->guest_R12;
    mach->__sp = vex->guest_R13;
    mach->__lr = vex->guest_R14;
    mach->__pc = vex->guest_R15T;
    mach->__cpsr = LibVEX_GuestARM_get_cpsr(vex);
}


static void arm_float_state32_from_vex(arm_vfp_state_t *mach, 
                                       VexGuestARMState *vex)
{
#  define SCFS2(reg,REG)  *(ULong *)(&mach->reg) = vex->guest_##REG
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
   mach->__fpscr = vex->guest_FPSCR;
#  undef SCFS2
}


void thread_state_from_vex(thread_state_t mach_generic, 
                           thread_state_flavor_t flavor, 
                           mach_msg_type_number_t count, 
                           VexGuestArchState *vex_generic)
{
   VexGuestARMState *vex = (VexGuestARMState *)vex_generic;

   switch (flavor) {
   case ARM_THREAD_STATE:
      vg_assert(count == ARM_THREAD_STATE_COUNT);
      arm_thread_state32_from_vex((arm_thread_state_t *)mach_generic, vex);
      break;
   case ARM_THREAD_STATE32:
      // Not Supported
      break;

   case ARM_VFP_STATE:
      vg_assert(count == ARM_VFP_STATE_COUNT);
      arm_float_state32_from_vex((arm_vfp_state_t *)mach_generic, vex);
      break;
      
   case ARM_EXCEPTION_STATE:
      VG_(printf)("thread_state_from_vex: TODO, want exception state\n");
      vg_assert(0);
       
   default:
      VG_(printf)("thread_state_from_vex: flavor:%#x\n",  flavor);
      vg_assert(0);
   }
}


static void arm_thread_state32_to_vex(const arm_thread_state_t *mach, 
                                      VexGuestARMState *vex)
{
   LibVEX_GuestARM_initialise(vex);
   vex->guest_R0 = mach->__r[0];
   vex->guest_R1 = mach->__r[1];
   vex->guest_R2 = mach->__r[2];
   vex->guest_R3 = mach->__r[3];
   vex->guest_R4 = mach->__r[4];
   vex->guest_R5 = mach->__r[5];
   vex->guest_R6 = mach->__r[6];
   vex->guest_R7 = mach->__r[7];
   vex->guest_R8 = mach->__r[8];
   vex->guest_R9 = mach->__r[9];
   vex->guest_R10 = mach->__r[10];
   vex->guest_R11 = mach->__r[11];
   vex->guest_R12 = mach->__r[12];
   vex->guest_R13 = mach->__sp;
   vex->guest_R14 = mach->__lr;
   vex->guest_R15T = mach->__pc;
   LibVEX_GuestARM_set_cpsr(mach->__cpsr, vex);
}

static void arm_float_state32_to_vex(const arm_vfp_state_t *mach, 
                                     VexGuestARMState *vex)
{
#  define SCFS2(reg,REG)  vex->guest_##REG = *(ULong *)(&mach->reg)
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
   vex->guest_FPSCR = mach->__fpscr;
#  undef SCFS2
}


void thread_state_to_vex(const thread_state_t mach_generic, 
                         thread_state_flavor_t flavor, 
                         mach_msg_type_number_t count, 
                         VexGuestArchState *vex_generic)
{
   VexGuestARMState *vex = (VexGuestARMState *)vex_generic;
   
   switch(flavor) {
   case ARM_THREAD_STATE:
      vg_assert(count == ARM_THREAD_STATE_COUNT);
      arm_thread_state32_to_vex((const arm_thread_state_t*)mach_generic,vex);
      break;
   case ARM_VFP_STATE:
      vg_assert(count == ARM_VFP_STATE_COUNT);
      arm_float_state32_to_vex((const arm_vfp_state_t*)mach_generic,vex);
      break;

   default:
      VG_(printf)("thread_state_to_vex: flavor:%#x\n",  flavor);
      vg_assert(0);
      break;
   }
}


ThreadState *build_thread(const thread_state_t state, 
                          thread_state_flavor_t flavor, 
                          mach_msg_type_number_t count)
{
   ThreadId tid = VG_(alloc_ThreadState)();
   ThreadState *tst = VG_(get_ThreadState)(tid);
    
   vg_assert(flavor == ARM_THREAD_STATE);
   vg_assert(count == ARM_THREAD_STATE_COUNT);

   // Initialize machine registers

   thread_state_to_vex(state, flavor, count, &tst->arch.vex);

   I_die_here;
   // GrP fixme signals, sig_mask, tmp_sig_mask, os_state.parent

   find_stack_segment(tid, tst->arch.vex.guest_R13);

   return tst;
}


// Edit the thread state to send to the real kernel.
// The real thread will run start_thread_NORETURN(tst)
// on a separate non-client stack.
void hijack_thread_state(thread_state_t mach_generic, 
                         thread_state_flavor_t flavor, 
                         mach_msg_type_number_t count, 
                         ThreadState *tst)
{
   arm_thread_state_t *mach = (arm_thread_state_t *)mach_generic;
   char *stack;

   vg_assert(flavor == ARM_THREAD_STATE);
   vg_assert(count == ARM_THREAD_STATE_COUNT);

   stack = (char *)allocstack(tst->tid);
   stack -= 64+320;                       // make room for top frame
   memset(stack, 0, 64+320);              // ...and clear it

   mach->__pc = (uintptr_t)&start_thread_NORETURN;
   mach->__sp = (uintptr_t)stack;
   mach->__lr = 0;                        // fake return address
   mach->__r[0] = (uintptr_t)tst;         // first parameter
}


/* Call f(arg1), but first switch stacks, using 'stack' as the new
   stack, and use 'retaddr' as f's return-to address.  Also, clear all
   the integer registers before entering f.*/
__attribute__((noreturn))
void call_on_new_stack_0_1 ( Addr stack,
			     Addr retaddr,
			     void (*f)(Word),
                             Word arg1 );
//  r0 == stack (must be 16-byte aligned)
//  r1 == retaddr
//  r2 == f
//  r3 == arg1
asm(
".globl _call_on_new_stack_0_1\n"
".align 4                     \n"
"_call_on_new_stack_0_1:\n"
"   mov    sp,r0\n\t" /* Stack pointer */
"   mov    lr,r1\n\t" /* Return address */
"   mov    r0,r3\n\t" /* First argument */
"   push   {r2}\n\t"  /* So we can ret to the new dest */
"   mov    r1, #0\n\t" /* Clear our GPRs */
"   mov    r2, #0\n\t"
"   mov    r3, #0\n\t"
"   mov    r4, #0\n\t"
"   mov    r5, #0\n\t"
"   mov    r6, #0\n\t"
"   mov    r7, #0\n\t"
"   mov    r8, #0\n\t"
"   mov    r9, #0\n\t"
"   mov    r10, #0\n\t"
"   mov    r11, #0\n\t"
"   mov    r12, #0\n\t"
"   pop    {pc}\n\t"  /* Herrre we go! */
);

// Check Apple's LIBC source code
// arm/pthreads/thread_start.s
// args 0 to 3 in r0-r3
// arg4 and 5 in r4-r5, put onto stack here for calling pthread_hijack
// anyway, later they will go into r4 and r5 in the vex state
asm(
".globl _pthread_hijack_asm\n"
".align 4                  \n"
"_pthread_hijack_asm:\n"
"   str sp, [sp, #-8]\n" //original sp into space
"   sub sp, #8\n" // alignment pad, space for the original sp
"   push {r5}\n"  // flags
"   push {r4}\n"  // stacksize
"   mov  lr,#0\n" // fake return address
"   b _pthread_hijack\n"
    );



void pthread_hijack(Addr self, Addr kport, Addr func, Addr func_arg, 
                    Addr stacksize, Addr flags, Addr sp)
{
   vki_sigset_t blockall;
   ThreadState *tst = (ThreadState *)func_arg;
   VexGuestARMState *vex = &tst->arch.vex;

   // VG_(printf)("pthread_hijack pthread %p, machthread %p, func %p, arg %p, stack %p, flags %p, stack %p\n", self, kport, func, func_arg, stacksize, flags, sp);

   // Wait for parent thread's permission.
   // The parent thread holds V's lock on our behalf.
   semaphore_wait(tst->os_state.child_go);

   /* Start the thread with all signals blocked.  VG_(scheduler) will
      set the mask correctly when we finally get there. */
   VG_(sigfillset)(&blockall);
   VG_(sigprocmask)(VKI_SIG_SETMASK, &blockall, NULL);

   // Set thread's registers
   // Do this FIRST because some code below tries to collect a backtrace, 
   // which requires valid register data.
   // DDD: need to do post_reg_write events here?
   LibVEX_GuestARM_initialise(vex);
   vex->guest_R15T = pthread_starter;
   vex->guest_R0 = self;
   vex->guest_R1 = kport;
   vex->guest_R2 = func;
   vex->guest_R3 = tst->os_state.func_arg;
   vex->guest_R4 = stacksize;
   vex->guest_R5 = flags;
   vex->guest_R13 = sp;

   // Record thread's stack and Mach port and pthread struct
   tst->os_state.pthread = self;
   tst->os_state.lwpid = kport;
   record_named_port(tst->tid, kport, MACH_PORT_RIGHT_SEND, "thread-%p");

   if ((flags & 0x01000000) == 0) {
      // kernel allocated stack - needs mapping
      Addr stack = VG_PGROUNDUP(sp) - stacksize;
      tst->client_stack_highest_byte = stack+stacksize-1;
      tst->client_stack_szB = stacksize;

      // pthread structure
      ML_(notify_core_and_tool_of_mmap)(
            stack+stacksize, pthread_structsize, 
            VKI_PROT_READ|VKI_PROT_WRITE, VKI_MAP_PRIVATE, -1, 0);
      // stack contents
      ML_(notify_core_and_tool_of_mmap)(
            stack, stacksize, 
            VKI_PROT_READ|VKI_PROT_WRITE, VKI_MAP_PRIVATE, -1, 0);
      // guard page
      ML_(notify_core_and_tool_of_mmap)(
            stack-VKI_PAGE_SIZE, VKI_PAGE_SIZE, 
            0, VKI_MAP_PRIVATE, -1, 0);
   } else {
      // client allocated stack
      find_stack_segment(tst->tid, sp);
   }
   ML_(sync_mappings)("after", "pthread_hijack", 0);

   // DDD: should this be here rather than in POST(sys_bsdthread_create)?
   // But we don't have ptid here...
   //VG_TRACK ( pre_thread_ll_create, ptid, tst->tid );

   // Tell parent thread's POST(sys_bsdthread_create) that we're done 
   // initializing registers and mapping memory.
   semaphore_signal(tst->os_state.child_done);
   // LOCK IS GONE BELOW THIS POINT

   // Go!
   call_on_new_stack_0_1(tst->os_state.valgrind_stack_init_SP, 0, 
                         start_thread_NORETURN, (Word)tst);

   /*NOTREACHED*/
   vg_assert(0);
}

// Check Apple's LIBC source code
// arm/pthreads/start_wqthread.s
// args 0 to 3 in r0-r3
// arg4 in r4, put onto stack here for calling wqthread_hijack
// anyway, later it will go into r4 in the vex state
asm(
".globl _wqthread_hijack_asm\n"
".align 4                   \n"
"_wqthread_hijack_asm:\n"
"   str sp, [sp, #-12]\n" //original sp into space
"   sub sp, #12\n" // 2 alignment pad, space for the original sp
"   push {r4}\n"  // reuse
"   mov  lr,#0\n" // fake return address
"   b    _wqthread_hijack\n"
    );

/*  wqthread note: The kernel may create or destroy pthreads in the 
    wqthread pool at any time with no userspace interaction, 
    and wqthread_start may be entered at any time with no userspace 
    interaction.
    To handle this in valgrind, we create and destroy a valgrind 
    thread for every work item.
*/
void wqthread_hijack(Addr self, Addr kport, Addr stackaddr, Addr workitem, 
                     Int reuse, Addr sp)
{
   ThreadState *tst;
   VexGuestARMState *vex;
   Addr stack;
   SizeT stacksize;
   vki_sigset_t blockall;

   /* When we enter here we hold no lock (!), so we better acquire it
      pronto.  Why do we hold no lock?  Because (presumably) the only
      way to get here is as a result of a SfMayBlock syscall
      "workq_ops(WQOPS_THREAD_RETURN)", which will have dropped the
      lock.  At least that's clear for the 'reuse' case.  The
      non-reuse case?  Dunno, perhaps it's a new thread the kernel
      pulled out of a hat.  In any case we still need to take a
      lock. */
   VG_(acquire_BigLock_LL)("wqthread_hijack");

   /* Start the thread with all signals blocked.  VG_(scheduler) will
      set the mask correctly when we finally get there. */
   VG_(sigfillset)(&blockall);
   VG_(sigprocmask)(VKI_SIG_SETMASK, &blockall, NULL);
   
   Int thread_reuse = 0;
   if (reuse & 0x00040000 /* == WQ_FLAG_THREAD_NEWSPI */) {
		thread_reuse = reuse & 0x00020000 /* == WQ_FLAG_THREAD_REUSE */;
	} else {
		thread_reuse = (reuse == 0)? 0: 0x00020000 /* == WQ_FLAG_THREAD_REUSE */;
	}

   if (thread_reuse) {

      /* For whatever reason, tst->os_state.pthread appear to have a
         constant offset of 72 on 10.7, but zero on 10.6 and 10.5.  No
         idea why. */
      // FIXME: measure magic_delta and put this back.
      /*
#     if DARWIN_VERS <= DARWIN_10_6
      UWord magic_delta = 0;
#     elif DARWIN_VERS >= DARWIN_10_7
      UWord magic_delta = 0x48;
#     endif
      */

      // This thread already exists; we're merely re-entering 
      // after leaving via workq_ops(WQOPS_THREAD_RETURN). 
      // Don't allocate any V thread resources.
      // Do reset thread registers.
      ThreadId tid = VG_(lwpid_to_vgtid)(kport);
      vg_assert(VG_(is_valid_tid)(tid));
      vg_assert(mach_thread_self() == kport);

      tst = VG_(get_ThreadState)(tid);

      if (0) VG_(printf)("wqthread_hijack reuse %s: tid %d, tst %p, "
                         "tst->os_state.pthread %#lx, self %#lx\n",
                         tst->os_state.pthread == self ? "SAME" : "DIFF",
                         tid, tst, tst->os_state.pthread, self);

      vex = &tst->arch.vex;
      // FIXME: measure magic_delta and put this check back.
      //vg_assert(tst->os_state.pthread - magic_delta == self);
   }
   else {
      // This is a new thread.
      tst = VG_(get_ThreadState)(VG_(alloc_ThreadState)());        
      vex = &tst->arch.vex;
      allocstack(tst->tid);
      LibVEX_GuestARM_initialise(vex);
   }
        
   // Set thread's registers
   // Do this FIRST because some code below tries to collect a backtrace, 
   // which requires valid register data.
   vex->guest_R15T = wqthread_starter;
   vex->guest_R0 = self;
   vex->guest_R1 = kport;
   vex->guest_R2 = stackaddr;
   vex->guest_R3 = workitem;
   vex->guest_R4 = reuse;
   vex->guest_R5 = 0;
   vex->guest_R13 = sp;

   stacksize = 512*1024;  // wq stacks are always DEFAULT_STACK_SIZE
   stack = VG_PGROUNDUP(sp) - stacksize;

   if (thread_reuse) {
       // Continue V's thread back in the scheduler. 
       // The client thread is of course in another location entirely.

      /* Drop the lock before going into
         ML_(wqthread_continue_NORETURN).  The latter will immediately
         attempt to reacquire it in non-LL mode, which is a bit
         wasteful but I don't think is harmful.  A better solution
         would be to not drop the lock but instead "upgrade" it from a
         LL lock to a full lock, but that's too much like hard work
         right now. */
       VG_(release_BigLock_LL)("wqthread_hijack(1)");
       ML_(wqthread_continue_NORETURN)(tst->tid);
   } 
   else {
      // Record thread's stack and Mach port and pthread struct
      tst->os_state.pthread = self;
      tst->os_state.lwpid = kport;
      record_named_port(tst->tid, kport, MACH_PORT_RIGHT_SEND, "wqthread-%p");
      
      // kernel allocated stack - needs mapping
      tst->client_stack_highest_byte = stack+stacksize-1;
      tst->client_stack_szB = stacksize;

      // GrP fixme scheduler lock?!
      
      // pthread structure
      ML_(notify_core_and_tool_of_mmap)(
            stack+stacksize, pthread_structsize, 
            VKI_PROT_READ|VKI_PROT_WRITE, VKI_MAP_PRIVATE, -1, 0);
      // stack contents
      // GrP fixme uninitialized!
      ML_(notify_core_and_tool_of_mmap)(
            stack, stacksize, 
            VKI_PROT_READ|VKI_PROT_WRITE, VKI_MAP_PRIVATE, -1, 0);
      // guard page
      // GrP fixme ban_mem_stack!
      ML_(notify_core_and_tool_of_mmap)(
            stack-VKI_PAGE_SIZE, VKI_PAGE_SIZE, 
            0, VKI_MAP_PRIVATE, -1, 0);

      ML_(sync_mappings)("after", "wqthread_hijack", 0);

      // Go!
      /* Same comments as the 'release' in the then-clause.
         start_thread_NORETURN calls run_thread_NORETURN calls
         thread_wrapper which acquires the lock before continuing.
         Let's hope nothing non-thread-local happens until that point.

         DDD: I think this is plain wrong .. if we get to
         thread_wrapper not holding the lock, and someone has recycled
         this thread slot in the meantime, we're hosed.  Is that
         possible, though? */
      VG_(release_BigLock_LL)("wqthread_hijack(2)");
      call_on_new_stack_0_1(tst->os_state.valgrind_stack_init_SP, 0, 
                            start_thread_NORETURN, (Word)tst);
   }

   /*NOTREACHED*/
   vg_assert(0);
}

/* ---------------------------------------------------------------------
   PRE/POST wrappers for arm/darwin-specific syscalls
   ------------------------------------------------------------------ */

#define PRE(name)       DEFN_PRE_TEMPLATE(arm_darwin, name)
#define POST(name)      DEFN_POST_TEMPLATE(arm_darwin, name)

/* Add prototypes for the wrappers declared here, so that gcc doesn't
   harass us for not having prototypes.  Really this is a kludge --
   the right thing to do is to make these wrappers 'static' since they
   aren't visible outside this file, but that requires even more macro
   magic. */

DECL_TEMPLATE(arm_darwin, csops_audittoken);
DECL_TEMPLATE(arm_darwin, shared_region_check_np);
DECL_TEMPLATE(arm_darwin, psynch_rw_longrdlock);   // 297
DECL_TEMPLATE(arm_darwin, psynch_rw_yieldwrlock);   // 298
DECL_TEMPLATE(arm_darwin, psynch_rw_downgrade);   // 299
DECL_TEMPLATE(arm_darwin, psynch_rw_upgrade);   // 300
DECL_TEMPLATE(arm_darwin, psynch_rw_unlock2);
DECL_TEMPLATE(arm_darwin, __old_semwait_signal); 
DECL_TEMPLATE(arm_darwin, __old_semwait_signal_nocancel); 
DECL_TEMPLATE(arm_darwin, ledger); 
DECL_TEMPLATE(arm_darwin, shared_region_map_and_slide_np); 
DECL_TEMPLATE(arm_darwin, proc_info); 

DECL_TEMPLATE(arm_darwin, sys_icache_invalidate); 
DECL_TEMPLATE(arm_darwin, sys_dcache_flush); 
DECL_TEMPLATE(arm_darwin, thread_fast_set_cthread_self); 
DECL_TEMPLATE(arm_darwin, ml_get_timebase);

PRE(csops_audittoken)
{
   PRINT("csops_audittoken ( %ld, %#lx, %#lx, %lu, %#lx )", ARG1, ARG2, ARG3, ARG4, ARG5);
   PRE_REG_READ5(int, "csops",
                 vki_pid_t, pid, uint32_t, ops,
                 void *, useraddr, vki_size_t, usersize,
                 vki_audit_token_t *, token);

   PRE_MEM_WRITE( "csops_audittoken(useraddr)", ARG3, ARG4 );
   PRE_MEM_READ( "csops_audittoken(useraddr)", ARG5, sizeof(vki_audit_token_t) );

   // If the pid is ours, don't mark the program as KILL or HARD
   // Maybe we should keep track of this for later calls to STATUS
   if (!ARG1 || VG_(getpid)() == ARG1) {
      switch (ARG2) {
      case VKI_CS_OPS_MARKINVALID:
      case VKI_CS_OPS_MARKHARD:
      case VKI_CS_OPS_MARKKILL:
         SET_STATUS_Success(0);
      }
   }
}
POST(csops_audittoken)
{
   POST_MEM_WRITE( ARG3, ARG4 );
}

PRE(shared_region_check_np)
{
   PRINT("shared_region_check_np ( %#lx )", ARG1);
}
POST(shared_region_check_np)
{
   uint64_t shared_region_addr = *(uint64_t *)ARG1;
   PRINT("shared_region_check_np: cachedBaseAddress = %llx", shared_region_addr);

   NSegment const* seg = VG_(am_find_nsegment)(shared_region_addr);
   if (seg) {
      if ((seg->kind == SkAnonV) || (seg->kind == SkAnonC)) {
         PRINT("\nSetting area owner from V to C...");
         Bool rv = VG_(am_change_ownership_v_to_c)(seg->start, seg->end - seg->start + 1);
         if (rv) {
            PRINT("OK");
         }
         else {
            PRINT("FAILED");
         }
      }
   }
   else {
      PRINT("...NOT FOUND");
   }
}

struct shared_file_mapping_np {
	mach_vm_address_t	sfm_address;
	mach_vm_size_t		sfm_size;
	mach_vm_offset_t	sfm_file_offset;
	vm_prot_t		   sfm_max_prot;
	vm_prot_t		   sfm_init_prot;
};

PRE(shared_region_map_and_slide_np)
{
   PRINT("shared_region_check_np ( %ld, %ld, %#lx, %ld, %#lx, %ld )", 
         ARG1, ARG2, ARG3, ARG4, ARG5, ARG6);
         
   PRE_REG_READ6(int, "shared_region_check_np",
                 int, fd, uint32_t, count,
                 void *, mappings, uint32_t, slide,
                 uint64_t *, slide_start,
                 uint32_t, slide_size);
}

POST(shared_region_map_and_slide_np)
{
   if (SUCCESS) {
      Int fd = ARG1;
      UInt count = ARG2;
      struct shared_file_mapping_np *mappings = ARG3;
      UInt slide = ARG4;
      int i = 0;
      while (i < count) {
         ML_(notify_core_and_tool_of_mmap)(mappings->sfm_address + slide, mappings->sfm_size, 
            mappings->sfm_init_prot & mappings->sfm_max_prot, VKI_MAP_SHARED, 
            fd, mappings->sfm_file_offset);
         i++;
         mappings++;
      }
   }
}

PRE(proc_info)
{
   PRINT("proc_info ( %ld, %ld, %lld, %ld, %ld, %ld )", 
         ARG1, ARG2, ARG3, (((uint64_t)ARG4) | ((uint64_t)ARG5 << 32)), ARG6, ARG7);
         
   PRE_REG_READ7(int, "proc_info",
                 int32_t, callnum, int32_t, pid,
                 uint32_t, flavor, uint32_t, argLo,
                 uint32_t, argHi, user_addr_t, buffer,
                 int32_t, buffersize);
   
}
POST(proc_info)
{
   
}

PRE(psynch_rw_longrdlock)
{
   PRINT("psynch_rw_longrdlock(BOGUS)");
   *flags |= SfMayBlock;
}
POST(psynch_rw_longrdlock)
{
}

PRE(psynch_rw_yieldwrlock)
{
   PRINT("psynch_rw_yieldwrlock(BOGUS)");
   *flags |= SfMayBlock;
}
POST(psynch_rw_yieldwrlock)
{
}

PRE(psynch_rw_downgrade)
{
   PRINT("psynch_rw_downgrade(BOGUS)");
}
POST(psynch_rw_downgrade)
{
}

PRE(psynch_rw_upgrade)
{
   PRINT("psynch_rw_upgrade(BOGUS)");
   *flags |= SfMayBlock;
}
POST(psynch_rw_upgrade)
{
}

PRE(psynch_rw_unlock2)
{
   PRINT("psynch_rw_unlock2(BOGUS)");
}
POST(psynch_rw_unlock2)
{
}

PRE(__old_semwait_signal)
{
   PRINT("__old_semwait_signal(wait %s, signal %s, %ld, %ld, %#lx)", 
         name_for_port(ARG1), name_for_port(ARG2), ARG3, ARG4, ARG5);
   PRE_REG_READ5(long, "__old_semwait_signal", 
                 int,"cond_sem", int,"mutex_sem",
                 int,"timeout", int,"relative", 
                 const struct vki_timespec *,ts);
                 
   if (ARG5) PRE_MEM_READ ("__old_semwait_signal(ts)", 
         ARG5, sizeof(struct vki_timespec));

   *flags |= SfMayBlock;
}

POST(__old_semwait_signal)
{
}

PRE(__old_semwait_signal_nocancel)
{
   PRINT("__old_semwait_signal_nocancel(wait %s, signal %s, %ld, %ld, %#lx)", 
         name_for_port(ARG1), name_for_port(ARG2), ARG3, ARG4, ARG5);
   PRE_REG_READ5(long, "__old_semwait_signal_nocancel", 
                 int,"cond_sem", int,"mutex_sem",
                 int,"timeout", int,"relative", 
                 const struct vki_timespec *,ts);
                 
   if (ARG5) PRE_MEM_READ ("__old_semwait_signal_nocancel(ts)", 
         ARG5, sizeof(struct vki_timespec));

   *flags |= SfMayBlock;
}

POST(__old_semwait_signal_nocancel)
{
}

//See: https://www.opensource.apple.com/source/xnu/xnu-2422.1.72/bsd/kern/sys_generic.c
//four args.
PRE(ledger)
{
   PRINT("ledger(cmd %ld, arg1 %#lx, arg2 %#lx, arg3 %#lx)", 
         ARG1, ARG2, ARG3, ARG4);
   PRE_REG_READ4(long, "ledger", 
                 int,"cmd", void *,"arg1",
                 void *,"arg2", void *,"arg3");
}

POST(ledger)
{
}

PRE(sys_icache_invalidate)
{
   PRINT("sys_icache_invalidate (%#lx, %#lx)",ARG1,ARG2);
   PRE_REG_READ2(long, "sys_icache_invalidate", void*, start, size_t, len);
   VG_(discard_translations)( (Addr64)ARG1,
                              (ULong)ARG2,
                              "PRE(sys_icache_invalidate)" );
   SET_STATUS_Success(0);
}

POST(sys_icache_invalidate)
{
}

PRE(sys_dcache_flush)
{
   PRINT("sys_dcache_flush (%#lx, %#lx)",ARG1,ARG2);
   PRE_REG_READ2(long, "sys_dcache_flush", void*, start, size_t, len);
}

POST(sys_dcache_flush)
{
}

PRE(thread_fast_set_cthread_self)
{
   PRINT("thread_fast_set_cthread_self ( %#lx )", ARG1);
   PRE_REG_READ1(void, "thread_fast_set_cthread_self", struct pthread_t *, self);

   ThreadState *tst = VG_(get_ThreadState)(tid);
   tst->os_state.pthread = ARG1;
   tst->arch.vex.guest_TPIDRURO = ((tst->arch.vex.guest_TPIDRURO & 0x3) | ARG1);
   
   SET_STATUS_from_SysRes(
      VG_(mk_SysRes_arm_darwin)(
         VG_DARWIN_SYSNO_CLASS(__NR_thread_fast_set_cthread_self),
         False, 0, 0x0
      )
   );
}

POST(thread_fast_set_cthread_self)
{
}

PRE(ml_get_timebase)
{
   PRINT("ml_get_timebase ()");
}

POST(ml_get_timebase)
{
}

/* ---------------------------------------------------------------------
   syscall tables: arm
   ------------------------------------------------------------------ */

/* Add a Darwin-specific, arch-independent wrapper to a syscall table. */
#define PMAX_(sysno, name)    WRAPPER_ENTRY_X_(arm_darwin, VG_DARWIN_SYSNO_INDEX(sysno), name) 
#define PMAXY(sysno, name)    WRAPPER_ENTRY_XY(arm_darwin, VG_DARWIN_SYSNO_INDEX(sysno), name)
#define _____(sysno) GENX_(sysno, sys_ni_syscall)  /* UNIX style only */

/*
     _____ : unsupported by the kernel (sys_ni_syscall) (UNIX-style only)
             unfortunately misused for Mach too, causing assertion failures
  // _____ : unimplemented in valgrind
     GEN   : handlers are in syswrap-generic.c
     MAC   : handlers are in this file
        X_ : PRE handler only
        XY : PRE and POST handlers
*/
const SyscallTableEntry ML_(syscall_table)[] = {
// _____(__NR_syscall),   // 0
   MACX_(__NR_exit,        exit), 
   GENX_(__NR_fork,        sys_fork), 
   GENXY(__NR_read,        sys_read), 
   GENX_(__NR_write,       sys_write), 
   GENXY(__NR_open,        sys_open), 
   GENXY(__NR_close,       sys_close), 
   GENXY(__NR_wait4,       sys_wait4), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(8)),     // old creat
   GENX_(__NR_link,        sys_link), 
   GENX_(__NR_unlink,      sys_unlink), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(11)),    // old execv
   GENX_(__NR_chdir,       sys_chdir), 
   GENX_(__NR_fchdir,      sys_fchdir), 
   GENX_(__NR_mknod,       sys_mknod), 
   GENX_(__NR_chmod,       sys_chmod), 
   GENX_(__NR_chown,       sys_chown), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(17)),    // old break
   MACXY(__NR_getfsstat,   getfsstat), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(19)),    // old lseek
   GENX_(__NR_getpid,      sys_getpid),     // 20
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(21)),    // old mount 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(22)),    // old umount
   GENX_(__NR_setuid,      sys_setuid), 
   GENX_(__NR_getuid,      sys_getuid), 
   GENX_(__NR_geteuid,     sys_geteuid), 
   MACX_(__NR_ptrace,      ptrace), 
   MACXY(__NR_recvmsg,     recvmsg), 
   MACX_(__NR_sendmsg,     sendmsg), 
   MACXY(__NR_recvfrom,    recvfrom), 
   MACXY(__NR_accept,      accept), 
   MACXY(__NR_getpeername, getpeername), 
   MACXY(__NR_getsockname, getsockname), 
   GENX_(__NR_access,      sys_access), 
   MACX_(__NR_chflags,     chflags), 
   MACX_(__NR_fchflags,    fchflags), 
   GENX_(__NR_sync,        sys_sync), 
   GENX_(__NR_kill,        sys_kill), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(38)),    // old stat
   GENX_(__NR_getppid,     sys_getppid), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(40)),    // old lstat
   GENXY(__NR_dup,         sys_dup), 
   MACXY(__NR_pipe,        pipe), 
   GENX_(__NR_getegid,     sys_getegid), 
// _____(__NR_profil), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(45)),    // old ktrace
   MACXY(__NR_sigaction,   sigaction), 
   GENX_(__NR_getgid,      sys_getgid), 
   MACXY(__NR_sigprocmask, sigprocmask), 
   MACXY(__NR_getlogin,    getlogin), 
// _____(__NR_setlogin), 
// _____(__NR_acct), 
   MACXY(__NR_sigpending,  sigpending),
   GENXY(__NR_sigaltstack, sys_sigaltstack), 
   MACXY(__NR_ioctl,       ioctl), 
// _____(__NR_reboot), 
// _____(__NR_revoke), 
   GENX_(__NR_symlink,     sys_symlink),   // 57
   GENX_(__NR_readlink,    sys_readlink), 
   GENX_(__NR_execve,      sys_execve), 
   GENX_(__NR_umask,       sys_umask),     // 60
   GENX_(__NR_chroot,      sys_chroot), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(62)),    // old fstat
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(63)),    // used internally, reserved
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(64)),    // old getpagesize
   GENX_(__NR_msync,       sys_msync), 
   GENX_(__NR_vfork,       sys_fork),              // (We treat vfork as fork.)
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(67)),    // old vread
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(68)),    // old vwrite
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(69)),    // old sbrk
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(70)),    // old sstk
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(71)),    // old mmap
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(72)),    // old vadvise
   GENXY(__NR_munmap,      sys_munmap), 
   GENXY(__NR_mprotect,    sys_mprotect), 
   GENX_(__NR_madvise,     sys_madvise), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(76)),    // old vhangup
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(77)),    // old vlimit
   GENXY(__NR_mincore,     sys_mincore), 
   GENXY(__NR_getgroups,   sys_getgroups), 
// _____(__NR_setgroups),   // 80
   GENX_(__NR_getpgrp,     sys_getpgrp), 
   GENX_(__NR_setpgid,     sys_setpgid), 
   GENXY(__NR_setitimer,   sys_setitimer), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(84)),    // old wait
// _____(__NR_swapon), 
   GENXY(__NR_getitimer,   sys_getitimer), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(87)),    // old gethostname
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(88)),    // old sethostname
   MACXY(__NR_getdtablesize, getdtablesize), 
   GENXY(__NR_dup2,        sys_dup2), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(91)),    // old getdopt
   MACXY(__NR_fcntl,       fcntl), 
   GENX_(__NR_select,      sys_select), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(94)),    // old setdopt
   GENX_(__NR_fsync,       sys_fsync), 
   GENX_(__NR_setpriority, sys_setpriority), 
   MACXY(__NR_socket,      socket), 
   MACX_(__NR_connect,     connect), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(99)),    // old accept
   GENX_(__NR_getpriority, sys_getpriority),   // 100
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(101)),   // old send
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(102)),   // old recv
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(103)),   // old sigreturn
   MACX_(__NR_bind,        bind), 
   MACX_(__NR_setsockopt,  setsockopt), 
   MACX_(__NR_listen,      listen), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(107)),   // old vtimes
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(108)),   // old sigvec
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(109)),   // old sigblock
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(110)),   // old sigsetmask
   MACX_(__NR_sigsuspend,  sigsuspend),            // old sigsuspend
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(112)),   // old sigstack
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(113)),   // old recvmsg
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(114)),   // old sendmsg
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(115)),   // old vtrace
   GENXY(__NR_gettimeofday, sys_gettimeofday), 
   GENXY(__NR_getrusage,   sys_getrusage), 
   MACXY(__NR_getsockopt,  getsockopt), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(119)),   // old resuba
   GENXY(__NR_readv,       sys_readv),        // 120
   GENX_(__NR_writev,      sys_writev), 
// _____(__NR_settimeofday), 
   GENX_(__NR_fchown,      sys_fchown), 
   GENX_(__NR_fchmod,      sys_fchmod), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(125)),   // old recvfrom
// _____(__NR_setreuid), 
// _____(__NR_setregid), 
   GENX_(__NR_rename,      sys_rename), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(129)),   // old truncate
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(130)),   // old ftruncate
   GENX_(__NR_flock,       sys_flock), 
// _____(__NR_mkfifo), 
   MACX_(__NR_sendto,      sendto), 
   MACX_(__NR_shutdown,    shutdown), 
   MACXY(__NR_socketpair,  socketpair), 
   GENX_(__NR_mkdir,       sys_mkdir), 
   GENX_(__NR_rmdir,       sys_rmdir), 
   GENX_(__NR_utimes,      sys_utimes), 
   MACX_(__NR_futimes,     futimes), 
// _____(__NR_adjtime),     // 140
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(141)),   // old getpeername
   MACXY(__NR_gethostuuid, gethostuuid), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(143)),   // old sethostid
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(144)),   // old getrlimit
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(145)),   // old setrlimit
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(146)),   // old killpg
   GENX_(__NR_setsid,      sys_setsid), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(148)),   // old setquota
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(149)),   // old qquota
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(150)),   // old getsockname 
// _____(__NR_getpgid), 
// _____(__NR_setprivexec), 
   GENXY(__NR_pread,       sys_pread64), 
   GENX_(__NR_pwrite,      sys_pwrite64), 
// _____(__NR_nfssvc), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(156)),   // old getdirentries
   GENXY(__NR_statfs,      sys_statfs), 
   GENXY(__NR_fstatfs,     sys_fstatfs), 
// _____(__NR_unmount), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(160)),   // old async_daemon
// _____(__NR_getfh), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(162)),   // old getdomainname
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(163)),   // old setdomainname
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(164)),   // ???
// _____(__NR_quotactl), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(166)),   // old exportfs
   MACX_(__NR_mount,       mount), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(168)),   // old ustat
   MACXY(__NR_csops,       csops),                 // code-signing ops
   PMAXY(__NR_csops_audittoken, csops_audittoken),   // 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(171)),   // old wait3
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(172)),   // old rpause
// _____(__NR_waitid), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(174)),   // old getdents
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(175)),   // old gc_control
// _____(__NR_add_profil), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(177)),   // ???
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(178)),   // ???
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(179)),   // ???
   MACX_(__NR_kdebug_trace, kdebug_trace),     // 180
   GENX_(__NR_setgid,      sys_setgid), 
   MACX_(__NR_setegid,     setegid), 
   MACX_(__NR_seteuid,     seteuid), 
   MACX_(__NR_sigreturn,   sigreturn), 
// _____(__NR_chud), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(186)),   // ??? 
// _____(__NR_fdatasync), 
   GENXY(__NR_stat,        sys_newstat), 
   GENXY(__NR_fstat,       sys_newfstat), 
   GENXY(__NR_lstat,       sys_newlstat), 
   MACX_(__NR_pathconf,    pathconf), 
   MACX_(__NR_fpathconf,   fpathconf), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(193)),   // ???
   GENXY(__NR_getrlimit,   sys_getrlimit), 
   GENX_(__NR_setrlimit,   sys_setrlimit), 
   MACXY(__NR_getdirentries, getdirentries), 
   MACXY(__NR_mmap,        mmap), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(198)),   // __syscall
   MACX_(__NR_lseek,       lseek), 
   GENX_(__NR_truncate,    sys_truncate64),   // 200
   GENX_(__NR_ftruncate,   sys_ftruncate64), 
   MACXY(__NR___sysctl,    __sysctl), 
   GENX_(__NR_mlock,       sys_mlock), 
   GENX_(__NR_munlock,     sys_munlock), 
// _____(__NR_undelete), 
// _____(__NR_ATsocket), 
// _____(__NR_ATgetmsg), 
// _____(__NR_ATputmsg), 
// _____(__NR_ATPsndreq), 
// _____(__NR_ATPsndrsp), 
// _____(__NR_ATPgetreq), 
// _____(__NR_ATPgetrsp), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(213)),   // Reserved for AppleTalk
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(214)),   // old kqueue_from_portset_np
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(215)),   // old kqueue_portset_np
// _____(__NR_mkcomplex), 
// _____(__NR_statv), 
// _____(__NR_lstatv), 
// _____(__NR_fstatv), 
   MACXY(__NR_getattrlist, getattrlist),   // 220
   MACX_(__NR_setattrlist, setattrlist), 
   MACXY(__NR_getdirentriesattr, getdirentriesattr), 
   MACX_(__NR_exchangedata,      exchangedata), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(224)),   // checkuseraccess
// _____(__NR_searchfs), 
   GENX_(__NR_delete,      sys_unlink), 
// _____(__NR_copyfile), 
// _____(__NR_fgetattrlist), 
// _____(__NR_fsetattrlist), 
   GENXY(__NR_poll,        sys_poll), 
   MACX_(__NR_watchevent,  watchevent), 
   MACXY(__NR_waitevent,   waitevent), 
   MACX_(__NR_modwatch,    modwatch), 
   MACXY(__NR_getxattr,    getxattr), 
   MACXY(__NR_fgetxattr,   fgetxattr), 
   MACX_(__NR_setxattr,    setxattr), 
   MACX_(__NR_fsetxattr,   fsetxattr), 
   MACX_(__NR_removexattr, removexattr), 
   MACX_(__NR_fremovexattr, fremovexattr), 
   MACXY(__NR_listxattr,   listxattr),    // 240
   MACXY(__NR_flistxattr,  flistxattr), 
   MACXY(__NR_fsctl,       fsctl), 
   MACX_(__NR_initgroups,  initgroups), 
   MACXY(__NR_posix_spawn, posix_spawn), 
// _____(__NR_ffsctl), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(246)),   // ???
// _____(__NR_nfsclnt), 
// _____(__NR_fhopen), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(249)),   // ???
// _____(__NR_minherit), 
// _____(__NR_semsys), 
// _____(__NR_msgsys), 
// _____(__NR_shmsys), 
   MACXY(__NR_semctl,      semctl), 
   MACX_(__NR_semget,      semget), 
   MACX_(__NR_semop,       semop), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(257)),   // ???
// _____(__NR_msgctl), 
// _____(__NR_msgget), 
// _____(__NR_msgsnd),   // 260
// _____(__NR_msgrcv), 
   MACXY(__NR_shmat,       shmat), 
   MACXY(__NR_shmctl,      shmctl), 
   MACXY(__NR_shmdt,       shmdt), 
   MACX_(__NR_shmget,      shmget), 
   MACXY(__NR_shm_open,    shm_open), 
   MACXY(__NR_shm_unlink,  shm_unlink), 
   MACX_(__NR_sem_open,    sem_open), 
   MACX_(__NR_sem_close,   sem_close), 
   MACX_(__NR_sem_unlink,  sem_unlink), 
   MACX_(__NR_sem_wait,    sem_wait), 
   MACX_(__NR_sem_trywait, sem_trywait), 
   MACX_(__NR_sem_post,    sem_post), 
// _____(__NR_sem_getvalue), 
   MACXY(__NR_sem_init,    sem_init), 
   MACX_(__NR_sem_destroy, sem_destroy), 
   MACX_(__NR_open_extended,  open_extended),    // 277
// _____(__NR_umask_extended), 
   MACXY(__NR_stat_extended,  stat_extended), 
   MACXY(__NR_lstat_extended, lstat_extended),   // 280
   MACXY(__NR_fstat_extended, fstat_extended), 
   MACX_(__NR_chmod_extended, chmod_extended), 
   MACX_(__NR_fchmod_extended,fchmod_extended), 
   MACXY(__NR_access_extended,access_extended), 
   MACX_(__NR_settid,         settid), 
   MACX_(__NR_gettid, gettid),  // 286
// _____(__NR_setsgroups), 
// _____(__NR_getsgroups), 
// _____(__NR_setwgroups), 
// _____(__NR_getwgroups), 
// _____(__NR_mkfifo_extended), 
// _____(__NR_mkdir_extended), 
// _____(__NR_identitysvc), 
   PMAXY(__NR_shared_region_check_np, shared_region_check_np), 
// _____(__NR_shared_region_map_np), 
// _____(__NR_vm_pressure_monitor), 
   PMAXY(__NR_psynch_rw_longrdlock, psynch_rw_longrdlock),   // 297
   PMAXY(__NR_psynch_rw_yieldwrlock, psynch_rw_yieldwrlock),   // 298
   PMAXY(__NR_psynch_rw_downgrade, psynch_rw_downgrade),   // 299
   PMAXY(__NR_psynch_rw_upgrade, psynch_rw_upgrade),   // 300
   MACXY(__NR_psynch_mutexwait, psynch_mutexwait), // 301
   MACXY(__NR_psynch_mutexdrop, psynch_mutexdrop), // 302
   MACXY(__NR_psynch_cvbroad,   psynch_cvbroad),   // 303
   MACXY(__NR_psynch_cvsignal,  psynch_cvsignal),  // 304
   MACXY(__NR_psynch_cvwait,    psynch_cvwait),    // 305
   MACXY(__NR_psynch_rw_rdlock, psynch_rw_rdlock), // 306
   MACXY(__NR_psynch_rw_wrlock, psynch_rw_wrlock), // 307
   MACXY(__NR_psynch_rw_unlock, psynch_rw_unlock), // 308
   PMAXY(__NR_psynch_rw_unlock2, psynch_rw_unlock2), // 309
// _____(__NR_getsid), 
// _____(__NR_settid_with_pid), 
   MACXY(__NR_psynch_cvclrprepost, psynch_cvclrprepost), // 312
// _____(__NR_aio_fsync), 
   MACXY(__NR_aio_return,     aio_return), 
   MACX_(__NR_aio_suspend,    aio_suspend), 
// _____(__NR_aio_cancel), 
   MACX_(__NR_aio_error,      aio_error), 
   MACXY(__NR_aio_read,       aio_read), 
   MACX_(__NR_aio_write,      aio_write), 
// _____(__NR_lio_listio),   // 320
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(321)),   // ???

   MACXY(__NR_iopolicysys, iopolicysys), 
   MACXY(__NR_process_policy, process_policy),
// _____(__NR_mlockall), 
// _____(__NR_munlockall), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(326)),   // ???
   MACX_(__NR_issetugid,               issetugid), 
   MACX_(__NR___pthread_kill,          __pthread_kill),
   MACX_(__NR___pthread_sigmask,       __pthread_sigmask), 
// _____(__NR___sigwait), 
   MACX_(__NR___disable_threadsignal,  __disable_threadsignal), 
   MACX_(__NR___pthread_markcancel,    __pthread_markcancel), 
   MACX_(__NR___pthread_canceled,      __pthread_canceled),
   MACX_(__NR___semwait_signal,        __semwait_signal), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(335)),   // old utrace
   PMAXY(__NR_proc_info,   proc_info),  // 336
   MACXY(__NR_sendfile,    sendfile), 
   MACXY(__NR_stat64,      stat64), 
   MACXY(__NR_fstat64,     fstat64), 
   MACXY(__NR_lstat64,     lstat64),    // 340
   MACXY(__NR_stat64_extended,  stat64_extended), 
   MACXY(__NR_lstat64_extended, lstat64_extended), 
   MACXY(__NR_fstat64_extended, fstat64_extended),
   MACXY(__NR_getdirentries64, getdirentries64), 
   MACXY(__NR_statfs64,    statfs64), 
   MACXY(__NR_fstatfs64,   fstatfs64), 
   MACXY(__NR_getfsstat64, getfsstat64), 
// _____(__NR___pthread_chdir), 
// _____(__NR___pthread_fchdir), 
// _____(__NR_audit), 
   MACXY(__NR_auditon,     auditon), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(352)),   // ???
// _____(__NR_getauid), 
// _____(__NR_setauid), 
// _____(__NR_getaudit), 
// _____(__NR_setaudit), 
   MACXY(__NR_getaudit_addr, getaudit_addr),
// _____(__NR_setaudit_addr), 
// _____(__NR_auditctl), 
   MACXY(__NR_bsdthread_create,     bsdthread_create),   // 360
   MACX_(__NR_bsdthread_terminate,  bsdthread_terminate), 
   MACXY(__NR_kqueue,      kqueue), 
   MACXY(__NR_kevent,      kevent), 
   GENX_(__NR_lchown,      sys_lchown), 
// _____(__NR_stack_snapshot), 
   MACX_(__NR_bsdthread_register, bsdthread_register), 
   MACX_(__NR_workq_open,  workq_open), 
   MACXY(__NR_workq_ops,   workq_ops), 
   MACXY(__NR_kevent64,      kevent64), 
   PMAXY(__NR___old_semwait_signal,      __old_semwait_signal), 
   PMAXY(__NR___old_semwait_signal_nocancel,      __old_semwait_signal_nocancel), 
   MACX_(__NR___thread_selfid, __thread_selfid), 
   PMAXY(__NR_ledger, ledger), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(374)),   // ???
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(375)),   // ???
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(376)),   // ???
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(377)),   // ???
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(378)),   // ???
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_UNIX(379)),   // ???
// _____(__NR___mac_execve),   // 380
   MACX_(__NR___mac_syscall, __mac_syscall),
// _____(__NR___mac_get_file),
// _____(__NR___mac_set_file),
// _____(__NR___mac_get_link),
// _____(__NR___mac_set_link),
// _____(__NR___mac_get_proc),
// _____(__NR___mac_set_proc),
// _____(__NR___mac_get_fd),
// _____(__NR___mac_set_fd),
// _____(__NR___mac_get_pid),
// _____(__NR___mac_get_lcid),
// _____(__NR___mac_get_lctx),
// _____(__NR___mac_set_lctx),
// _____(__NR_setlcid),
// _____(__NR_getlcid),
   // GrP fixme need any special nocancel handling?
   GENXY(__NR_read_nocancel,     sys_read),
   GENX_(__NR_write_nocancel,    sys_write),
   GENXY(__NR_open_nocancel,     sys_open),
   GENXY(__NR_close_nocancel,    sys_close),
   GENXY(__NR_wait4_nocancel,    sys_wait4),   // 400
   MACXY(__NR_recvmsg_nocancel,  recvmsg),
   MACX_(__NR_sendmsg_nocancel,  sendmsg),
   MACXY(__NR_recvfrom_nocancel, recvfrom),
   MACXY(__NR_accept_nocancel,   accept),
   GENX_(__NR_msync_nocancel,    sys_msync),
   MACXY(__NR_fcntl_nocancel,    fcntl),
   GENX_(__NR_select_nocancel,   sys_select),
   GENX_(__NR_fsync_nocancel,    sys_fsync),
   MACX_(__NR_connect_nocancel,  connect),
// _____(__NR_sigsuspend_nocancel),
   GENXY(__NR_readv_nocancel,    sys_readv),
   GENX_(__NR_writev_nocancel,   sys_writev),
   MACX_(__NR_sendto_nocancel,   sendto),
   GENXY(__NR_pread_nocancel,    sys_pread64),
   GENX_(__NR_pwrite_nocancel,   sys_pwrite64),
// _____(__NR_waitid_nocancel),
   GENXY(__NR_poll_nocancel,     sys_poll),
// _____(__NR_msgsnd_nocancel),
// _____(__NR_msgrcv_nocancel),
   MACX_(__NR_sem_wait_nocancel, sem_wait), // 420
// _____(__NR_aio_suspend_nocancel),
// _____(__NR___sigwait_nocancel),
   MACX_(__NR___semwait_signal_nocancel, __semwait_signal), 
// _____(__NR___mac_mount),
// _____(__NR___mac_get_mount),
// _____(__NR___mac_getfsstat),
   MACXY(__NR_fsgetpath, fsgetpath), 
   MACXY(__NR_audit_session_self, audit_session_self),
// _____(__NR_audit_session_join),
    MACX_(__NR_fileport_makeport, fileport_makeport),
// _____(__NR_fileport_makefd),
// _____(__NR_audit_session_port),
// _____(__NR_pid_suspend),
// _____(__NR_pid_resume),
// _____(__NR_pid_hibernate),
// _____(__NR_pid_shutdown_sockets),      //436

   PMAXY(__NR_shared_region_map_and_slide_np, shared_region_map_and_slide_np),
// _____(__NR_kas_info),
// _____(__NR_memorystatus_control),
    
    MACX_(__NR_guarded_open_np, guarded_open_np),
    MACX_(__NR_guarded_close_np, guarded_close_np),
    MACX_(__NR_guarded_kqueue_np, guarded_kqueue_np),
    MACX_(__NR_change_fdguard_np, change_fdguard_np),
    
// _____(__NR_proc_rlimit_control),       //446
    MACX_(__NR_connectx, connectx),
    MACX_(__NR_disconnectx, disconnectx),
// _____(__NR_peeloff), 
// _____(__NR_socket_delegate), 
// _____(__NR_telemetry), 
// _____(__NR_proc_uuid_policy), 
// _____(__NR_memorystatus_get_level), 
// _____(__NR_system_override), 
// _____(__NR_vfs_purge), 

// _____(__NR_MAXSYSCALL)
   MACX_(__NR_DARWIN_FAKE_SIGRETURN, FAKE_SIGRETURN)
};


// Mach traps use negative syscall numbers. 
// Use ML_(mach_trap_table)[-mach_trap_number] .
// cf xnu sources osfmk/kern/syscall_sw.c

const SyscallTableEntry ML_(mach_trap_table)[] = {
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(0)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(1)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(2)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(3)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(4)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(5)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(6)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(7)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(8)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(9)), 

   MACXY(__NR_kernelrpc_mach_vm_allocate_trap, kernelrpc_mach_vm_allocate_trap),

   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(11)), 

   MACXY(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(12), kernelrpc_mach_vm_deallocate_trap),

   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(13)), 

   MACX_(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(14), kernelrpc_mach_vm_protect_trap),

   MACXY(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(15), kernelrpc_mach_vm_map_trap),

//   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(14)), 
//   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(15)), 

   MACXY(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(16), kernelrpc_mach_port_allocate_trap),
   MACX_(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(17), kernelrpc_mach_port_destroy_trap),
   MACX_(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(18), kernelrpc_mach_port_deallocate_trap),
   MACX_(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(19), kernelrpc_mach_port_mod_refs_trap),
   MACX_(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(20), kernelrpc_mach_port_move_member_trap),
   MACX_(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(21), kernelrpc_mach_port_insert_right_trap),
   MACX_(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(22), kernelrpc_mach_port_insert_member_trap),
   MACX_(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(23), kernelrpc_mach_port_extract_member_trap),
   MACX_(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(24), kernelrpc_mach_port_construct_trap),
   MACX_(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(25), kernelrpc_mach_port_destruct_trap),

   MACXY(__NR_mach_reply_port, mach_reply_port), 
   MACXY(__NR_thread_self_trap, mach_thread_self), 
   MACXY(__NR_task_self_trap, mach_task_self), 
   MACXY(__NR_host_self_trap, mach_host_self), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(30)), 
   MACXY(__NR_mach_msg_trap, mach_msg), 
// _____(__NR_mach_msg_overwrite_trap), 
   MACX_(__NR_semaphore_signal_trap, semaphore_signal), 
   MACX_(__NR_semaphore_signal_all_trap, semaphore_signal_all), 
   MACX_(__NR_semaphore_signal_thread_trap, semaphore_signal_thread), 
   MACX_(__NR_semaphore_wait_trap, semaphore_wait), 
   MACX_(__NR_semaphore_wait_signal_trap, semaphore_wait_signal), 
   MACX_(__NR_semaphore_timedwait_trap, semaphore_timedwait), 
   MACX_(__NR_semaphore_timedwait_signal_trap, semaphore_timedwait_signal), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(40)),    // -40
   MACX_(__NR_kernelrpc_mach_port_guard_trap, kernelrpc_mach_port_guard_trap),
   MACX_(__NR_kernelrpc_mach_port_unguard_trap, kernelrpc_mach_port_unguard_trap),
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(43)), 
// _____(__NR_task_name_for_pid), 
   MACXY(__NR_task_for_pid, task_for_pid), 
   MACXY(__NR_pid_for_task, pid_for_task), 
// _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(47)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(48)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(49)), 
// _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(50)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(51)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(52)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(53)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(54)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(55)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(56)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(57)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(58)), 
   MACX_(__NR_swtch_pri, swtch_pri), 
   MACX_(__NR_swtch, swtch),   // -60
   MACX_(__NR_syscall_thread_switch, syscall_thread_switch), 
// _____(__NR_clock_sleep_trap), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(63)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(64)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(65)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(66)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(67)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(68)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(69)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(70)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(71)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(72)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(73)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(74)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(75)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(76)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(77)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(78)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(79)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(80)),   // -80
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(81)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(82)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(83)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(84)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(85)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(86)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(87)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(88)), 
   MACXY(__NR_mach_timebase_info, mach_timebase_info), 
   MACX_(__NR_mach_wait_until, mach_wait_until), 
   MACXY(__NR_mk_timer_create, mk_timer_create), 
   MACXY(__NR_mk_timer_destroy, mk_timer_destroy), 
   MACX_(__NR_mk_timer_arm, mk_timer_arm), 
   MACXY(__NR_mk_timer_cancel, mk_timer_cancel), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(95)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(96)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(97)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(98)), 
   _____(VG_DARWIN_SYSCALL_CONSTRUCT_MACH(99)), 
   MACXY(__NR_iokit_user_client_trap, iokit_user_client_trap), // -100
};


// Machine-dependent traps have wacky syscall numbers, and use the Mach trap 
// calling convention instead of the syscall convention.
// Use ML_(mdep_trap_table)[syscallno - ML_(mdep_trap_base)] .

const SyscallTableEntry ML_(mdep_trap_table)[] = {
   PMAXY(__NR_sys_icache_invalidate, sys_icache_invalidate), 
   PMAXY(__NR_sys_dcache_flush, sys_dcache_flush), 
   PMAX_(__NR_thread_fast_set_cthread_self, thread_fast_set_cthread_self), 
};

const SyscallTableEntry ML_(ml_trap_table)[] = {
   PMAXY(__NR_ml_get_timebase, ml_get_timebase), 
};

const UInt ML_(syscall_table_size) = 
            sizeof(ML_(syscall_table)) / sizeof(ML_(syscall_table)[0]);

const UInt ML_(mach_trap_table_size) = 
            sizeof(ML_(mach_trap_table)) / sizeof(ML_(mach_trap_table)[0]);

const UInt ML_(mdep_trap_table_size) = 
            sizeof(ML_(mdep_trap_table)) / sizeof(ML_(mdep_trap_table)[0]);

const UInt ML_(ml_trap_table_size) = 
            sizeof(ML_(ml_trap_table)) / sizeof(ML_(ml_trap_table)[0]);

#endif // defined(VGP_arm_darwin)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
