/*--------------------------------------------------------------------*/
/*--- Basic Mach traps.                    mach_traps-arm-darwin.S ---*/
/*--------------------------------------------------------------------*/

/*
   This file is part of Valgrind, a dynamic binary instrumentation
   framework.

   Copyright (C) 2006-2013 Apple Inc.
      Greg Parker  gparker@apple.com

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

#include "pub_core_vkiscnums_asm.h"

#if defined(VGP_arm_darwin)

// DDD: should use __NR_ constants in here instead of the trap numbers
// directly!

	// mach_port_name_t task_self_trap(void)
	.text
	.align 4
	.globl _task_self_trap
_task_self_trap:
	mov	r12, #VG_DARWIN_SYSNO_FOR_KERNEL_MACH(__NR_task_self_trap)
	svc #0x80
	bx lr

	// mach_port_name_t host_self_trap(void)
	.text
	.align 4
	.globl _host_self_trap
_host_self_trap:
	mov	r12, #VG_DARWIN_SYSNO_FOR_KERNEL_MACH(__NR_host_self_trap)
	svc #0x80
	bx lr

	// mach_port_name_t thread_self_trap(void)
	.text
	.align 4
	.globl _thread_self_trap
_thread_self_trap:
	mov	r12, #VG_DARWIN_SYSNO_FOR_KERNEL_MACH(__NR_thread_self_trap)
	svc #0x80
	bx lr

	// mach_msg_return_t mach_msg_trap(...)
	.text
	.align 4
	.globl _mach_msg_trap
_mach_msg_trap:
    mov r12, sp
    stmfd sp!, {r4-r6, r8}
    ldmia r12, {r4-r6}
	mov	r12, #VG_DARWIN_SYSNO_FOR_KERNEL_MACH(__NR_mach_msg_trap)
	svc #0x80
    ldmfd sp!, {r4-r6, r8}
	bx lr

	// mach_port_t mach_reply_port(void)
	.text
	.align 4
	.globl _mach_reply_port
_mach_reply_port:
	mov	r12, #VG_DARWIN_SYSNO_FOR_KERNEL_MACH(__NR_mach_reply_port)
	svc #0x80
	bx lr

	// boolean_t swtch_pri(int)
	.text
	.align 4
	.globl _swtch_pri
_swtch_pri:
	mov	r12, #VG_DARWIN_SYSNO_FOR_KERNEL_MACH(__NR_swtch_pri)
	svc #0x80
	bx lr

	// kern_return_t semaphore_wait(semaphore_t)
	.text
	.align 4
	.globl _semaphore_wait
_semaphore_wait:
	mov	r12, #VG_DARWIN_SYSNO_FOR_KERNEL_MACH(__NR_semaphore_wait_trap)
	svc #0x80
	bx lr

	// kern_return_t semaphore_signal(semaphore_t)
	.text
	.align 4
	.globl _semaphore_signal
_semaphore_signal:
	mov	r12, #VG_DARWIN_SYSNO_FOR_KERNEL_MACH(__NR_semaphore_signal_trap)
	svc #0x80
	bx lr

	// kern_return_t semaphore_signal_thread(semaphore_t, thread_t)
	.text
	.align 4
	.globl _semaphore_signal_thread
_semaphore_signal_thread:
	mov	r12, #VG_DARWIN_SYSNO_FOR_KERNEL_MACH(__NR_semaphore_signal_thread_trap)
	svc #0x80
	bx lr

	// kern_return_t semaphore_wait_signal(semaphore_t, semaphore_t)
	.text
	.align 4
	.globl _semaphore_wait_signal
_semaphore_wait_signal:
	mov	r12, #VG_DARWIN_SYSNO_FOR_KERNEL_MACH(__NR_semaphore_wait_signal_trap)
	svc #0x80
	bx lr

#endif // defined(VGP_arm_darwin)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
