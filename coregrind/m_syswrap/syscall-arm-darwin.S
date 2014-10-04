
/*--------------------------------------------------------------------*/
/*--- Support for doing system calls.         syscall-arm-darwin.S ---*/
/*--------------------------------------------------------------------*/

/*
  This file is part of Valgrind, a dynamic binary instrumentation
  framework.

  Copyright (C) 2014 Zhui Deng ( dengd03@gmail.com )

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

#include "pub_core_basics_asm.h"
#include "pub_core_vkiscnums_asm.h"
#include "libvex_guest_offsets.h"


/*----------------------------------------------------------------*/
/*
	Perform a syscall for the client.  This will run a syscall
	with the client's specific per-thread signal mask.
	
	The structure of this function is such that, if the syscall is
	interrupted by a signal, we can determine exactly what
	execution state we were in with respect to the execution of
	the syscall by examining the value of %eip in the signal
	handler.  This means that we can always do the appropriate
	thing to precisely emulate the kernel's signal/syscall
	interactions.

	The syscall number is taken from the argument, even though it
	should also be in guest_state->R12.  The syscall result
	is written back to guest_state->R0 on completion.
	
	Returns 0 if the syscall was successfully called (even if the
	syscall itself failed), or a -ve error code if one of the
	sigprocmasks failed (there's no way to determine which one
	failed).

	VG_(fixup_guest_state_after_syscall_interrupted) does the
	thread state fixup in the case where we were interrupted by a
	signal.
	
	Prototype:

	Int ML_(do_syscall_for_client_WRK(
	                          Int syscallno,		// r0
				  void* guest_state,		// r1
				  const vki_sigset_t *sysmask,	// r2
				  const vki_sigset_t *postmask,	// r3
				  Int sigsetSzB)		// [sp, #0]

        Note that sigsetSzB is totally ignored (and irrelevant).
*/

/* from vki_arch.h */	
#define VKI_SIG_SETMASK	3

/* DO_SYSCALL MACH|MDEP|UNIX */
#define MACH 1
#define MDEP 2
#define UNIX 3

.macro DO_SYSCALL
	/* save callee-saved regs and those to be used as local var */
	push    {r4-r7, r8, r10, r11, lr}
    // maintain frame pointer
    add     r7, sp, #0xc

	// stack is now aligned, total used 0x20

    // Make the frame like the syscall wrapper.
    // This is only for syscall with >=8 arguments. When <8 arguments,
    // the stack is not used anyway.

    // Load the SP value when client called SVC #80
    ldr     r12, [r1, #OFFSET_arm_R13]

    // get over r4-r6, r8 saved by the syscall wrapper
    add     r12, r12, #0x10

    // r4-r6, r8 holds the args passed to the syscall wrapper
    ldmia   r12, {r4-r6, r8}

    // save them onto stack
    stmfd   sp!, {r4-r6, r8}

    // make the frame like the syscall wrapper, which saves {r4-r6, r8}
    sub     sp, sp, #0x10

	// stack is now aligned, total used 0x40

    mov r4, r0      //r4 = syscall number
    mov r10, r1     //r10 = guest_state
    mov r11, r2      //r11 = sysmask

L_$0_1:	/* Even though we can't take a signal until the sigprocmask completes,
	   start the range early.
	   If rip is in the range [1,2), the syscall hasn't been started yet */

	mov r12, # VG_DARWIN_SYSNO_FOR_KERNEL_UNIX(__NR___pthread_sigmask)
    mov r0, #VKI_SIG_SETMASK
    mov r1, r11 /* sysmask */
    mov r2, r3 /* postmask */
    svc #0x80
    bcs L_$0_7 /* __pthread_sigmask failed */
	
	/* OK, that worked.  Now do the syscall proper. */

.if $0 == UNIX
    /* at most 7 register parameters */
	mov	r12, r4
	ldr r0, [r10, #OFFSET_arm_R0]
	ldr r1, [r10, #OFFSET_arm_R1]
	ldr r2, [r10, #OFFSET_arm_R2]
	ldr r3, [r10, #OFFSET_arm_R3]
	ldr r4, [r10, #OFFSET_arm_R4]
	ldr r5, [r10, #OFFSET_arm_R5]
	ldr r6, [r10, #OFFSET_arm_R6]
.elseif $0 == MACH
    /* all register parameters, currently max 8 */
	mov	r12, r4
	ldr r0, [r10, #OFFSET_arm_R0]
	ldr r1, [r10, #OFFSET_arm_R1]
	ldr r2, [r10, #OFFSET_arm_R2]
	ldr r3, [r10, #OFFSET_arm_R3]
	ldr r4, [r10, #OFFSET_arm_R4]
	ldr r5, [r10, #OFFSET_arm_R5]
	ldr r6, [r10, #OFFSET_arm_R6]
    ldr r8, [r10, #OFFSET_arm_R8]
.elseif $0 == MDEP
    /* only r0, r1, r2 register params */
    /* r3 is the mdep call number */
    /* r12 is 0x80000000 */
    mov r3, r4
    mov r12, #0x80000000
	ldr r0, [r10, #OFFSET_arm_R0]
	ldr r1, [r10, #OFFSET_arm_R1]
	ldr r2, [r10, #OFFSET_arm_R2]
.else
	error$0 x
.endif

    /* NOTE: r3 no longer holds postmask after here */

	/* If rip==2, then the syscall was either just about
	   to start, or was interrupted and the kernel was 
	   restarting it. */
L_$0_2:	svc #0x80
L_$0_3:	/* In the range [3, 4), the syscall result is in r0, r1 and cpsr.c,
	   but hasn't been committed to R0. */

	str r0, [r10, #OFFSET_arm_R0]
    str r1, [r10, #OFFSET_arm_R1]

.if $0 == UNIX
	/* save carry flag to VEX */
    mov     r0, #0
	movcs   r0, #1	/* arg1 = new flag */
	mov     r1, r10	/* arg2 = vex state */
	bl      _LibVEX_GuestARM_put_cpsr_c
.endif

L_$0_4:	/* Re-block signals.  If eip is in [4,5), then the syscall 
	   is complete and we needn't worry about it. */
	mov r12, # VG_DARWIN_SYSNO_FOR_KERNEL_UNIX(__NR___pthread_sigmask)
    mov r0, #VKI_SIG_SETMASK
    mov r1, r11 /* sysmask */
    mov r2, #0  /* postmask */
    svc #0x80
    bcs L_$0_7 /* __pthread_sigmask failed */

L_$0_5:	/* now safe from signals */
    mov     r0, #0
    add     sp, sp, #0x10
    ldmfd   sp!, {r4-r6, r8}
    pop     {r4-r7, r8, r10, r11, pc}

L_$0_7: /* Failure: return 0x8000 | error code */
    mov     r1, #0x8000
    sub     r1, #0x1
    and     r0, r0, r1
    orr     r0, r0, #0x8000

    add     sp, sp, #0x10
    ldmfd   sp!, {r4-r6, r8}
    pop     {r4-r7, r8, r10, r11, pc}

.endmacro

	
.globl ML_(do_syscall_for_client_unix_WRK)
.align 4
ML_(do_syscall_for_client_unix_WRK):
	DO_SYSCALL UNIX

.globl ML_(do_syscall_for_client_mach_WRK)
.align 4
ML_(do_syscall_for_client_mach_WRK):
	DO_SYSCALL MACH
	
.globl ML_(do_syscall_for_client_mdep_WRK)
.align 4
ML_(do_syscall_for_client_mdep_WRK):
	DO_SYSCALL MDEP

.data
/* export the ranges so that
   VG_(fixup_guest_state_after_syscall_interrupted) can do the
   right thing */

/* eg MK_L_SCLASS_N(UNIX,99) produces L_3_99
   since UNIX is #defined to 3 at the top of this file */
#define FOO(scclass,labelno) L_##scclass##_##labelno
#define MK_L_SCCLASS_N(scclass,labelno) FOO(scclass,labelno)

.globl ML_(blksys_setup_MACH)
.globl ML_(blksys_restart_MACH)
.globl ML_(blksys_complete_MACH)
.globl ML_(blksys_committed_MACH)
.globl ML_(blksys_finished_MACH)
ML_(blksys_setup_MACH):	.long MK_L_SCCLASS_N(MACH,1)
ML_(blksys_restart_MACH):	.long MK_L_SCCLASS_N(MACH,2)
ML_(blksys_complete_MACH):	.long MK_L_SCCLASS_N(MACH,3)
ML_(blksys_committed_MACH):	.long MK_L_SCCLASS_N(MACH,4)
ML_(blksys_finished_MACH):	.long MK_L_SCCLASS_N(MACH,5)

.globl ML_(blksys_setup_MDEP)
.globl ML_(blksys_restart_MDEP)
.globl ML_(blksys_complete_MDEP)
.globl ML_(blksys_committed_MDEP)
.globl ML_(blksys_finished_MDEP)
ML_(blksys_setup_MDEP):	.long MK_L_SCCLASS_N(MDEP,1)
ML_(blksys_restart_MDEP):	.long MK_L_SCCLASS_N(MDEP,2)
ML_(blksys_complete_MDEP):	.long MK_L_SCCLASS_N(MDEP,3)
ML_(blksys_committed_MDEP):	.long MK_L_SCCLASS_N(MDEP,4)
ML_(blksys_finished_MDEP):	.long MK_L_SCCLASS_N(MDEP,5)

.globl ML_(blksys_setup_UNIX)
.globl ML_(blksys_restart_UNIX)
.globl ML_(blksys_complete_UNIX)
.globl ML_(blksys_committed_UNIX)
.globl ML_(blksys_finished_UNIX)
ML_(blksys_setup_UNIX):	.long MK_L_SCCLASS_N(UNIX,1)
ML_(blksys_restart_UNIX):	.long MK_L_SCCLASS_N(UNIX,2)
ML_(blksys_complete_UNIX):	.long MK_L_SCCLASS_N(UNIX,3)
ML_(blksys_committed_UNIX):	.long MK_L_SCCLASS_N(UNIX,4)
ML_(blksys_finished_UNIX):	.long MK_L_SCCLASS_N(UNIX,5)

#endif // defined(VGP_arm_darwin)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
