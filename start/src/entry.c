#include <common.h>

int main();
void _init() __attribute__((weak));
void _fini() __attribute__((weak));
_Noreturn int __libc_start_main(int (*)(), int, char **,
	void (*)(), void(*)(), void(*)());

int __exit_code;
EFI_HANDLE gImageHandle;
EFI_SYSTEM_TABLE* gST;
EFI_RUNTIME_SERVICES* gRT;
EFI_BOOT_SERVICES* gBS;
void* stack_base;
size_t stack_size;

static EFI_HOB_MEMORY_ALLOCATION_STACK* mStackHob = NULL;
static jmp_buf __abort_jmpbuf;
static void* mHobList = NULL;
static EFI_GUID gEfiHobListGuid = { 0x7739F24C, 0x93D7, 0x11D4, { 0x9A, 0x3A, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D }};
static EFI_GUID gEfiHobMemoryAllocStackGuid = { 0x4ED4BF27, 0x4092, 0x42E9, { 0x80, 0x7D, 0x52, 0x7B, 0x1D, 0x00, 0xC9, 0xBD }};

void uefi_do_assert (const char* filename, size_t lineno, const char* exp) {
    uefi_printf ("UEFI_ASSERT %s(%d): %s\n", filename, lineno, exp);
    longjmp(__abort_jmpbuf, 1);
    for(;;);
}

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

BOOLEAN
EFIAPI
CompareGuid (
  IN CONST GUID  *Guid1,
  IN CONST GUID  *Guid2
  )
{
    UEFI_ASSERT(Guid1);
    UEFI_ASSERT(Guid2);
    return (memcmp(Guid1, Guid2, sizeof(GUID)) == 0) ? TRUE : FALSE;
}

EFI_STATUS
EFIAPI
EfiGetSystemConfigurationTable (
  IN  EFI_GUID  *TableGuid,
  OUT VOID      **Table
  )
{
  EFI_SYSTEM_TABLE  *SystemTable;
  UINTN             Index;

  UEFI_ASSERT(TableGuid);
  UEFI_ASSERT(Table);

  SystemTable = gST;
  *Table = NULL;
  for (Index = 0; Index < SystemTable->NumberOfTableEntries; Index++) {
    if (CompareGuid (TableGuid, &(SystemTable->ConfigurationTable[Index].VendorGuid))) {
      *Table = SystemTable->ConfigurationTable[Index].VendorTable;
      return EFI_SUCCESS;
    }
  }

  return EFI_NOT_FOUND;
}

VOID *
EFIAPI
GetNextHob (
  IN UINT16                 Type,
  IN CONST VOID             *HobStart
  )
{
  EFI_PEI_HOB_POINTERS  Hob;

  UEFI_ASSERT(HobStart);
   
  Hob.Raw = (UINT8 *) HobStart;
  //
  // Parse the HOB list until end of list or matching type is found.
  //
  while (!END_OF_HOB_LIST (Hob)) {
    if (Hob.Header->HobType == Type) {
      return Hob.Raw;
    }
    Hob.Raw = GET_NEXT_HOB (Hob);
  }
  return NULL;
}

EFI_HOB_MEMORY_ALLOCATION_STACK* GetStackHob(void) {
  EFI_PEI_HOB_POINTERS           Hob;

  Hob.Raw = mHobList;
  while ((Hob.Raw = GetNextHob (EFI_HOB_TYPE_MEMORY_ALLOCATION, Hob.Raw)) != NULL) {
    if (CompareGuid (&gEfiHobMemoryAllocStackGuid, &(Hob.MemoryAllocationStack->AllocDescriptor.Name))) {
      return Hob.MemoryAllocationStack;
    }
    Hob.Raw = GET_NEXT_HOB (Hob);
  }

  return NULL;
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
    EFI_STATUS Status;

    gImageHandle = ImageHandle;
    gST = SystemTable;
    gRT = gST->RuntimeServices;
    gBS = gST->BootServices;

    uefi_init_printf(NULL, internal_putc);
    uefi_printf("entry\n");

    // set abort handler
    rc = setjmp (__abort_jmpbuf);
    if (rc) {
        return EFI_SUCCESS;
    }

    // get hob list
    Status = EfiGetSystemConfigurationTable (&gEfiHobListGuid, &mHobList);
    if(EFI_ERROR(Status)) {
        uefi_printf("can't get efi hob list\n");
        return Status;
    }

    // get stack hob
    mStackHob = GetStackHob();
    if(mStackHob==NULL) {
        uefi_printf("can't get stack hob\n");
        return EFI_SUCCESS;
    }

    // get stack information and allocate copy buffer
    stack_base = (void*)(UINTN)mStackHob->AllocDescriptor.MemoryBaseAddress;
    stack_size = (UINTN)mStackHob->AllocDescriptor.MemoryLength;
    stack_copy = AllocateZeroPool(stack_size);

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
    rc = setjmp (rootprocess->return_jmpbuf);
    if (rc) {
        uefi_printf("exit with %d\n", rootprocess->exit_code);
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
