#include <common.h>

int main();
void _init() __attribute__((weak));
void _fini() __attribute__((weak));
_Noreturn int __libc_start_main(int (*)(), int, char **,
	void (*)(), void(*)(), void(*)());

jmp_buf __exit_jmpbuf;
int __exit_code;
EFI_HANDLE gImageHandle;
EFI_SYSTEM_TABLE* gST;
EFI_RUNTIME_SERVICES* gRT;
EFI_BOOT_SERVICES* gBS;

VOID *
InternalAllocatePool (
  IN EFI_MEMORY_TYPE  MemoryType,  
  IN UINTN            AllocationSize
  )
{
  EFI_STATUS  Status;
  VOID        *Memory;

  Status = gBS->AllocatePool (MemoryType, AllocationSize, &Memory);
  if (EFI_ERROR (Status)) {
    Memory = NULL;
  }
  return Memory;
}

VOID *
EFIAPI
AllocatePool (
  IN UINTN  AllocationSize
  )
{
  return InternalAllocatePool (EfiBootServicesData, AllocationSize);
}

VOID *
EFIAPI
AllocateZeroPool (
  IN UINTN  AllocationSize
  )
{
  VOID  *Memory;

  Memory = InternalAllocatePool (EfiBootServicesData, AllocationSize);
  if (Memory != NULL) {
    Memory = memset (Memory, 0, AllocationSize);
  }
  return Memory;
}

static void internal_putc (unused void* p, char c) {
    uint8_t buf[4] = {0};

    buf[0] = c;
    gST->ConOut->OutputString(gST->ConOut, (uint16_t*)buf);
}

EFI_STATUS
EFIAPI
_ModuleEntryPoint (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
    int rc = 0;
    UINTN num_args = 1;
    UINTN num_envs = 0;
    UINTN num_auxs = 0;
    CONST CHAR8* program_name = "/usr/bin/fake";
    UINTN tmpsz;

    gImageHandle = ImageHandle;
    gST = SystemTable;
    gRT = gST->RuntimeServices;
    gBS = gST->BootServices;

    uefi_init_printf(NULL, internal_putc);
    uefi_printf("entry\n");

    __syscall_init();

    // allocate data pointer
    UINTN phdr_len = ROUNDUP(sizeof(UINTN) * (1 + num_args+1 + num_envs+1) + sizeof(Elf_auxv_t) * num_auxs+1, 16);
    UINTN pdata_len = strlen(program_name)+1 + 0 + sizeof(UINTN);
    UINTN* pmem = AllocateZeroPool(phdr_len + pdata_len);
    if(!pmem) return EFI_OUT_OF_RESOURCES;
    UINTN* p = pmem;
    UINT8* pdata = ((UINT8*)p)+phdr_len;

    // argc
    *p++ = num_args;

    // argv
    tmpsz = strlen(program_name)+1;
    memcpy(pdata, program_name, tmpsz);
    *p++ = (UINTN)pdata;
    pdata += tmpsz;
    *p++ = (UINTN)NULL;

    // envp
    *p++ = (UINTN)NULL;

    // auxv
    Elf_auxv_t* pauxv = (Elf_auxv_t*)p;
    pauxv->a_type = AT_NULL;

    // set exit handler
    rc = setjmp (__exit_jmpbuf);
    if (rc) {
        uefi_printf("exit with %d\n", __exit_code);
        return EFI_SUCCESS;
    }

    int argc = pmem[0];
	char **argv = (void *)(pmem+1);
    rc = __libc_start_main(main, argc, argv, _init, _fini, 0);
    if(rc) {
        uefi_printf("returned with %d\n", rc);
        return EFI_LOAD_ERROR;
    }

    return EFI_SUCCESS;
}
