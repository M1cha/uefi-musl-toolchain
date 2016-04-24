/*
 * Copyright 2016, The EFIDroid Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#ifndef _PRIVATE_H
#define _PRIVATE_H

// UEFI
#include <Base.h>
#include <Uefi.h>
#include <PiDxe.h>
#include <Library/HobLib.h>
#undef NULL

// STDLIB
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <syscall.h>
#include <stdarg.h>
#include <setjmp.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <poll.h>
#include <limits.h>
#include <malloc.h>

#define ROUNDUP(a, b) (((a) + ((b)-1)) & ~((b)-1))
#define unused __attribute__((unused))

void uefi_do_assert (const char* filename, size_t lineno, const char* exp);
#define _UEFI_ASSERT(Expression)  uefi_do_assert (__FILE__, __LINE__, #Expression)
#define UEFI_ASSERT(Expression)        \
do {                            \
    if (!(Expression)) {        \
      _UEFI_ASSERT (Expression);     \
    }                           \
} while (0)

// PRIVATE
#include "syscalls.h"
#include "list.h"

typedef Elf32_auxv_t Elf_auxv_t;

typedef struct {
    list_node_t node;

    int pid;
    int tid;
    int ppid;
    list_node_t fds;
    int process_dumpable;
    char cwd[PATH_MAX+1];

    // exit
    jmp_buf return_jmpbuf;
    int exit_code;
    void* stack_backup;

    // threads
    int __user* clear_child_tid;
    long tls ;

    // fork
    //int has_vfork_status;
    //int vfork_status;
} process_t;

extern jmp_buf __exit_jmpbuf;
extern int __exit_code;
extern EFI_HANDLE gImageHandle;
extern EFI_SYSTEM_TABLE* gST;
extern EFI_RUNTIME_SERVICES* gRT;
extern EFI_BOOT_SERVICES* gBS;
extern void* stack_base;
extern size_t stack_size;
extern void* stack_copy;

int setjmp_stack (jmp_buf, void* stack_backup);
_Noreturn void longjmp_stack (jmp_buf, int, void* stack_backup);

process_t* __syscall_init(void);
void uefi_init_printf(void *putp, void (*putf) (void *, char));
void uefi_printf(const char *fmt, ...);

VOID *
EFIAPI
AllocatePool (
  IN UINTN  AllocationSize
  );

VOID *
EFIAPI
AllocateZeroPool (
  IN UINTN  AllocationSize
  );

#endif // _PRIVATE_H
