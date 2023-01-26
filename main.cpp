#include "mem.h"
#include "utils.h"
#include "imports.h"
#include <intrin.h>
#include "adc.h"
#include "nt.hpp"
#include <ntimage.h>
typedef signed char        int8_t;
typedef short              int16_t;
typedef int                int32_t;
typedef long long          int64_t;
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
ULONGLONG PoolNumberOfBytes;
uint64_t IsClear = 1;
#define RVA(addr, size)			((PBYTE)(addr + *(DWORD*)(addr + ((size) - 4)) + size))
#define printf(text, ...)		(DbgPrintEx(0, 0, text, ##__VA_ARGS__))
BOOLEAN RemovePfnDatabaseEntry(_In_ uint64_t Address)
{
	if (PoolNumberOfBytes == 0x00)
		return FALSE;

	PMDL mdl = IoAllocateMdl((PVOID)Address, PoolNumberOfBytes, FALSE, FALSE, NULL);


	if (!mdl)
		return FALSE;

	PPFN_NUMBER mdl_pages = MmGetMdlPfnArray(mdl);

	if (!mdl_pages)
		return FALSE;

	ULONG mdl_page_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));

	ULONG null_pfn = 0x0;

	MM_COPY_ADDRESS source_address = { 0 };

	source_address.VirtualAddress = &null_pfn;

	for (ULONG i = 0; i < mdl_page_count; i++)
	{
		size_t bytes = 0;
		MmCopyMemory(&mdl_pages[i], source_address, sizeof(ULONG), MM_COPY_MEMORY_VIRTUAL, &bytes);
	}

	RtlZeroMemory(&mdl, sizeof(&mdl));

	RtlZeroMemory(&mdl_pages, sizeof(&mdl_pages));

	return TRUE;
}
PVOID GetProcessBaseAddress(int pid)
{
	PEPROCESS pProcess = NULL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);

	PVOID Base = PsGetProcessSectionBaseAddress(pProcess);
	ObDereferenceObject(pProcess);
	return Base;
}
//https://ntdiff.github.io/
#define WINDOWS_1803 17134
#define WINDOWS_1809 17763
#define WINDOWS_1903 18362
#define WINDOWS_1909 18363
#define WINDOWS_2004 19041
#define WINDOWS_20H2 19569
#define WINDOWS_21H1 20180
//0x18 bytes (sizeof)
typedef struct _POOL_TRACKER_BIG_PAGES
{
	volatile ULONGLONG Va;                                                  //0x0
	ULONG Key;                                                              //0x8
	ULONG Pattern : 8;                                                        //0xc
	ULONG PoolType : 12;                                                      //0xc
	ULONG SlushSize : 12;                                                     //0xc
	ULONGLONG NumberOfBytes;                                                //0x10
}POOL_TRACKER_BIG_PAGES, * PPOOL_TRACKER_BIG_PAGES;
DWORD GetUserDirectoryTableBaseOffset()
{
	RTL_OSVERSIONINFOW ver = { 0 };
	RtlGetVersion(&ver);

	switch (ver.dwBuildNumber)
	{
	case WINDOWS_1803:
		return 0x0278;
		break;
	case WINDOWS_1809:
		return 0x0278;
		break;
	case WINDOWS_1903:
		return 0x0280;
		break;
	case WINDOWS_1909:
		return 0x0280;
		break;
	case WINDOWS_2004:
		return 0x0388;
		break;
	case WINDOWS_20H2:
		return 0x0388;
		break;
	case WINDOWS_21H1:
		return 0x0388;
		break;
	default:
		return 0x0388;
	}
}
#define PAGE_OFFSET_SIZE 12
static const uint64_t PMASK = (~0xfull << 8) & 0xfffffffffull;

//check normal dirbase if 0 then get from UserDirectoryTableBas
ULONG_PTR GetProcessCr3(PEPROCESS pProcess)
{
	PUCHAR process = (PUCHAR)pProcess;
	ULONG_PTR process_dirbase = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
	if (process_dirbase == 0)
	{
		DWORD UserDirOffset = GetUserDirectoryTableBaseOffset();
		ULONG_PTR process_userdirbase = *(PULONG_PTR)(process + UserDirOffset);
		return process_userdirbase;
	}
	return process_dirbase;
}
ULONG_PTR GetKernelDirBase()
{
	PUCHAR process = (PUCHAR)PsGetCurrentProcess();
	ULONG_PTR cr3 = *(PULONG_PTR)(process + 0x28); //dirbase x64, 32bit is 0x18
	return cr3;
}

NTSTATUS ReadPhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesRead)
{
	MM_COPY_ADDRESS AddrToRead = { 0 };
	AddrToRead.PhysicalAddress.QuadPart = (LONGLONG)TargetAddress;
	return MmCopyMemory(lpBuffer, AddrToRead, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}
uint64_t TranslateLinearAddress(uint64_t directoryTableBase, uint64_t virtualAddress) {
	directoryTableBase &= ~0xf;

	uint64_t pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
	uint64_t pte = ((virtualAddress >> 12) & (0x1ffll));
	uint64_t pt = ((virtualAddress >> 21) & (0x1ffll));
	uint64_t pd = ((virtualAddress >> 30) & (0x1ffll));
	uint64_t pdp = ((virtualAddress >> 39) & (0x1ffll));

	SIZE_T readsize = 0;
	uint64_t pdpe = 0;
	ReadPhysicalAddress((PVOID)(directoryTableBase + 8 * pdp), &pdpe, sizeof(pdpe), &readsize);
	if (~pdpe & 1)
		return 0;

	uint64_t pde = 0;
	ReadPhysicalAddress((PVOID)((pdpe & PMASK) + 8 * pd), &pde, sizeof(pde), &readsize);
	if (~pde & 1)
		return 0;

	/* 1GB large page, use pde's 12-34 bits */
	if (pde & 0x80)
		return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

	uint64_t pteAddr = 0;
	ReadPhysicalAddress((PVOID)((pde & PMASK) + 8 * pt), &pteAddr, sizeof(pteAddr), &readsize);
	if (~pteAddr & 1)
		return 0;

	/* 2MB large page */
	if (pteAddr & 0x80)
		return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

	virtualAddress = 0;
	ReadPhysicalAddress((PVOID)((pteAddr & PMASK) + 8 * pte), &virtualAddress, sizeof(virtualAddress), &readsize);
	virtualAddress &= PMASK;

	if (!virtualAddress)
		return 0;

	return virtualAddress + pageOffset;
}
NTSTATUS ReadVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* read)
{
	uint64_t paddress = TranslateLinearAddress(dirbase, address);
	return ReadPhysicalAddress((PVOID)paddress, buffer, size, read);
}

//MmMapIoSpaceEx limit is page 4096 byte
NTSTATUS WritePhysicalAddress(PVOID TargetAddress, PVOID lpBuffer, SIZE_T Size, SIZE_T* BytesWritten)
{
	if (!TargetAddress)
		return STATUS_UNSUCCESSFUL;

	PHYSICAL_ADDRESS AddrToWrite = { 0 };
	AddrToWrite.QuadPart = (LONGLONG)TargetAddress;

	PVOID pmapped_mem = MmMapIoSpaceEx(AddrToWrite, Size, PAGE_READWRITE);

	if (!pmapped_mem)
		return STATUS_UNSUCCESSFUL;

	memcpy(pmapped_mem, lpBuffer, Size);

	*BytesWritten = Size;
	MmUnmapIoSpace(pmapped_mem, Size);
	return STATUS_SUCCESS;
}
NTSTATUS WriteVirtual(uint64_t dirbase, uint64_t address, uint8_t* buffer, SIZE_T size, SIZE_T* written)
{
	uint64_t paddress = TranslateLinearAddress(dirbase, address);
	return WritePhysicalAddress((PVOID)paddress, buffer, size, written);

}
uint64_t RDrvGetModuleEntry(PEPROCESS Process, UNICODE_STRING
	module_name)
{
	if (!Process) return STATUS_INVALID_PARAMETER_1;
	PPEB peb = PsGetProcessPeb(Process);

	if (!peb) {
		return 0;
	}
	KAPC_STATE state;
	KeStackAttachProcess(Process, &state);
	PPEB_LDR_DATA ldr = peb->Ldr;

	if (!ldr)
	{
		KeUnstackDetachProcess(&state);
		return 0; // failed
	}

	for (PLIST_ENTRY listEntry = (PLIST_ENTRY)ldr->ModuleListLoadOrder.Flink;
		listEntry != &ldr->ModuleListLoadOrder;
		listEntry = (PLIST_ENTRY)listEntry->Flink)
	{

		PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		if (RtlCompareUnicodeString(&ldrEntry->BaseDllName, &module_name, TRUE) ==
			0) {
			ULONG64 baseAddr = (ULONG64)ldrEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return baseAddr;
		}

	}
	KeUnstackDetachProcess(&state);

	return 0;
}

static uint64_t handle_get_peb(int pid)
{
	PEPROCESS process = nullptr;
	NTSTATUS  status = PsLookupProcessByProcessId(HANDLE(pid), &process);

	if (!NT_SUCCESS(status))
		return false;

	UNICODE_STRING DLLName;
	RtlInitUnicodeString(&DLLName, L"UnityPlayer.dll");
	const auto base_address = RDrvGetModuleEntry(process, DLLName);

	ObDereferenceObject(process);

	return base_address;
}

static uint64_t handle_get_peb1(int pid)
{
	PEPROCESS process = nullptr;
	NTSTATUS  status = PsLookupProcessByProcessId(HANDLE(pid), &process);

	if (!NT_SUCCESS(status))
		return false;

	UNICODE_STRING DLLName;
	RtlInitUnicodeString(&DLLName, L"GameAssembly.dll");
	const auto base_address = RDrvGetModuleEntry(process, DLLName);

	ObDereferenceObject(process);

	return base_address;
}


//
NTSTATUS ReadProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size)
{
	PEPROCESS pProcess = NULL;
	if (pid == 0) return STATUS_UNSUCCESSFUL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
	if (NtRet != STATUS_SUCCESS) return NtRet;

	ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
	ObDereferenceObject(pProcess);

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = size;
	while (TotalSize)
	{

		uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 ReadSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesRead = 0;
		NtRet = ReadPhysicalAddress((PVOID)CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), ReadSize, &BytesRead);
		TotalSize -= BytesRead;
		CurOffset += BytesRead;
		if (NtRet != STATUS_SUCCESS) break;
		if (BytesRead == 0) break;
	}

	return NtRet;
}

NTSTATUS WriteProcessMemory(int pid, PVOID Address, PVOID AllocatedBuffer, SIZE_T size)
{
	PEPROCESS pProcess = NULL;
	if (pid == 0) return STATUS_UNSUCCESSFUL;

	NTSTATUS NtRet = PsLookupProcessByProcessId((HANDLE)pid, &pProcess);
	if (NtRet != STATUS_SUCCESS) return NtRet;

	ULONG_PTR process_dirbase = GetProcessCr3(pProcess);
	ObDereferenceObject(pProcess);

	SIZE_T CurOffset = 0;
	SIZE_T TotalSize = size;
	while (TotalSize)
	{
		uint64_t CurPhysAddr = TranslateLinearAddress(process_dirbase, (ULONG64)Address + CurOffset);
		if (!CurPhysAddr) return STATUS_UNSUCCESSFUL;

		ULONG64 WriteSize = min(PAGE_SIZE - (CurPhysAddr & 0xFFF), TotalSize);
		SIZE_T BytesWritten = 0;
		NtRet = WritePhysicalAddress((PVOID)CurPhysAddr, (PVOID)((ULONG64)AllocatedBuffer + CurOffset), WriteSize, &BytesWritten);
		TotalSize -= BytesWritten;
		CurOffset += BytesWritten;
		if (NtRet != STATUS_SUCCESS) break;
		if (BytesWritten == 0) break;
	}

	return NtRet;
}
PIMAGE_NT_HEADERS getHeader(PVOID module) {
	return (PIMAGE_NT_HEADERS)((PBYTE)module + PIMAGE_DOS_HEADER(module)->e_lfanew);
}

PBYTE FindPattern12(PVOID module, DWORD size, LPCSTR pattern, LPCSTR mask) {

	auto checkMask = [](PBYTE buffer, LPCSTR pattern, LPCSTR mask) -> BOOL
	{
		for (auto x = buffer; *mask; pattern++, mask++, x++) {
			auto addr = *(BYTE*)(pattern);
			if (addr != *x && *mask != '?')
				return FALSE;
		}

		return TRUE;
	};

	for (auto x = 0; x < size - strlen(mask); x++) {

		auto addr = (PBYTE)module + x;
		if (checkMask(addr, pattern, mask))
			return addr;
	}

	return NULL;
}
char* lower_string(char* str) {
	for (char* s = str; *s; ++s)
		*s = static_cast<char>(tolower(*s));

	return str;
}
typedef struct _SYSTEM_MODULE {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[MAXIMUM_FILENAME_LENGTH];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG NumberOfModules;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

uintptr_t get_module_base(const char* name) {
	uint32_t size;
	auto status = ZwQuerySystemInformation(0xb, 0, 0, reinterpret_cast<PULONG>(&size));

	if (STATUS_INFO_LENGTH_MISMATCH != status)
		return 0;

	const auto modules = static_cast<PSYSTEM_MODULE_INFORMATION>(ExAllocatePool(NonPagedPool, size));

	if (modules == nullptr)
		return 0;

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(0xb, modules, size, 0))) {
		ExFreePool(modules);
		return 0;
	}

	for (size_t i = 0; i < modules->NumberOfModules; ++i) {
		auto mod = modules->Modules[i];

		if (strstr(lower_string(reinterpret_cast<char*>(mod.FullPathName)), name) != nullptr) {
			ExFreePool(modules);
			return reinterpret_cast<uintptr_t>(mod.ImageBase);
		}
	}

	ExFreePool(modules);

	return 0;
}
PVOID return_DLL_base_addr(PEPROCESS pe_process, UNICODE_STRING module_name) {
	if (!pe_process)
		return nullptr;

	PPEB peb = PsGetProcessPeb(pe_process);

	if (!peb)
		return nullptr;

	KAPC_STATE state;
	KeStackAttachProcess(pe_process, &state);
	PPEB_LDR_DATA ldr = peb->Ldr;

	if (!ldr)
	{
		KeUnstackDetachProcess(&state);
		return 0;
	}

	for (PLIST_ENTRY listEntry = (PLIST_ENTRY)ldr->ModuleListLoadOrder.Flink; listEntry != &ldr->ModuleListLoadOrder; listEntry = (PLIST_ENTRY)listEntry->Flink) {
		PLDR_DATA_TABLE_ENTRY ldrEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

		if (RtlCompareUnicodeString(&ldrEntry->BaseDllName, &module_name, TRUE) == 0) {
			PVOID baseAddr = ldrEntry->DllBase;
			KeUnstackDetachProcess(&state);
			return baseAddr;
		}

	}

	KeUnstackDetachProcess(&state);

	return 0;
}
PBYTE FindPattern1(PVOID base, LPCSTR pattern, LPCSTR mask) {

	auto header = getHeader(base);
	auto section = IMAGE_FIRST_SECTION(header);

	for (auto x = 0; x < header->FileHeader.NumberOfSections; x++, section++) {

		/*
		* Avoids non paged memory,
		* As well as greatly speeds up the process of scanning 30+ sections.
		*/
		if (!memcmp(section->Name, ".text", 5) || !memcmp(section->Name, "PAGE", 4)) {
			auto addr = FindPattern12((PBYTE)base + section->VirtualAddress, section->Misc.VirtualSize, pattern, mask);
			if (addr) {
				return addr;
			}
		}
	}

	return NULL;
}
bool FindPoolTable(uint64_t* pPoolBigPageTable, uint64_t* pPoolBigPageTableSize)
{
	auto b = mem::GetSystemBaseModule(skCrypt("\\SystemRoot\\system32\\ntoskrnl.exe"));
	auto Pat1 = skCrypt("\xE8\x00\x00\x00\x00\x83\x67\x0C\x00");
	auto Mask1 = skCrypt("x????xxxx");
	PVOID ExProtectPoolExCallInstructionsAddress = (PVOID)cleaner::FindPattern((uint64_t)b, 0xFFFFFF, (BYTE*)Pat1.decrypt(), Mask1.decrypt());
	Pat1.clear();
	Mask1.clear();

	if (!ExProtectPoolExCallInstructionsAddress)
		return false;

	PVOID ExProtectPoolExAddress = cleaner::ResolveRelativeAddress(ExProtectPoolExCallInstructionsAddress, 1, 5);

	if (!ExProtectPoolExAddress)
		return false;

	PVOID PoolBigPageTableInstructionAddress = (PVOID)((ULONG64)ExProtectPoolExAddress + 0x95);
	*pPoolBigPageTable = (uint64_t)cleaner::ResolveRelativeAddress(PoolBigPageTableInstructionAddress, 3, 7);

	PVOID PoolBigPageTableSizeInstructionAddress = (PVOID)((ULONG64)ExProtectPoolExAddress + 0x8E);
	*pPoolBigPageTableSize = (uint64_t)cleaner::ResolveRelativeAddress(PoolBigPageTableSizeInstructionAddress, 3, 7);

	return true;
}

bool RemoveFromBigPool(uint64_t Address)
{
	uint64_t pPoolBigPageTable = 0;
	uint64_t pPoolBigPageTableSize = 0;

	if (FindPoolTable(&pPoolBigPageTable, &pPoolBigPageTableSize))
	{

		PPOOL_TRACKER_BIG_PAGES PoolBigPageTable = 0;
		RtlCopyMemory(&PoolBigPageTable, (PVOID)pPoolBigPageTable, 8);
		SIZE_T PoolBigPageTableSize = 0;
		RtlCopyMemory(&PoolBigPageTableSize, (PVOID)pPoolBigPageTableSize, 8);

		for (int i = 0; i < PoolBigPageTableSize; i++)
		{
			if (PoolBigPageTable[i].Va == Address || PoolBigPageTable[i].Va == (Address + 0x1))
			{
				PoolNumberOfBytes = PoolBigPageTable[i].NumberOfBytes;
				PoolBigPageTable[i].Va = 0x1;
				PoolBigPageTable[i].NumberOfBytes = 0x0;
				return true;
			}
		}

		return false;
	}

	return false;
}
bool clearci() {
	auto b = mem::GetSystemBaseModule(skCrypt("\\SystemRoot\\system32\\CI.dll"));
	auto size1 = (UINT64)mem::GetSystemBaseSize(skCrypt("\\SystemRoot\\system32\\CI.dll"));
	if(!b) return false;
	auto Pat1 = skCrypt("\x8B\xD8\xFF\x05\x00\x00\x00\x00");
	auto Mask1 = skCrypt("xxxx????");
	PVOID g_CiEaCacheLookasideList = (PVOID)cleaner::FindPattern((uint64_t)b, size1, (BYTE*)Pat1.decrypt(), Mask1.decrypt());
	if (!g_CiEaCacheLookasideList)return false;
	g_CiEaCacheLookasideList = (PVOID)((uintptr_t)g_CiEaCacheLookasideList + 8);
	PVOID a = cleaner::ResolveRelativeAddress(g_CiEaCacheLookasideList, 3, 7);
	PLOOKASIDE_LIST_EX ci = (PLOOKASIDE_LIST_EX)a;
	SIZE_T size = ci->L.Size;
	auto ac = ci->L.TotalAllocates;
	ExDeleteLookasideListEx(ci);
	ExInitializeLookasideListEx(ci, NULL, NULL, PagedPool, 0, size, 'csIC', 0);
	auto c = ci->L.TotalAllocates;
	return true;
} 
void* NtCompositionInputThread_ret = nullptr;
__int64(__fastcall* NtCompositionInputThread)();

__int64(__fastcall* GreDxgkEnableUnorderedWaitsForDevice)();

/// <summary>
/// Gres the LDDM process lock screen hk.
/// </summary>
/// <param name="a1">The a1.</param>
/// <param name="a2">The a2.</param>
/// <returns></returns>
__int64 __fastcall GreDxgkEnableUnorderedWaitsForDevice_hk(uintptr_t a1, PVOID a2) {
	//if (ExGetPreviousMode() != UserMode) {
	//	return gre_lddm_process_lock_screen();
	uintptr_t* frame = (uintptr_t*)_AddressOfReturnAddress();
	uintptr_t stacktop = 0;
	uintptr_t stackbottom = 0;
	IoGetStackLimits(&stacktop, &stackbottom);
	uint32_t stacksize = (stackbottom - (uintptr_t)frame) / 8;
	DebugPrint("Original addr call : %llx\n", (uintptr_t)NtCompositionInputThread_ret);
	for (UINT32 i = 0; i < stacksize; i++)
	{
		DebugPrint("Frame call : %llx\n",frame[i]);
		if (frame[i] == (uintptr_t)NtCompositionInputThread_ret)
		{
			DebugPrint("suc be call\n");
			if (a1 == 0x47DFAED4774 && a2 != NULL) 
			{
				DebugPrint("suc call\n");
				MEMORY_STRUCT* m = (MEMORY_STRUCT*)a2;

				if (m->magic == 0x1337)
				{
					if (m->type == 1)
					{
						//Simple check to know if the driver is available
						m->output = (void*)0x9999;

					}
					//PLOOKASIDE_LIST_EX ci = (PLOOKASIDE_LIST_EX)g_CiEaCacheLookasideList;
					else if (m->type == 3)
					{
						//Read process memory
						if (!m->address || !m->size || !m->output || !m->target_pid || !m->usermode_pid) return STATUS_INVALID_PARAMETER_1;
						PEPROCESS usermode_process;
						if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->usermode_pid, &usermode_process)))
						{
							PEPROCESS tg_process;
							if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->target_pid, &tg_process)))
							{
								if (m->address > (void*)0x1000 && m->address < (void*)0x7FFFFFFEFFFF)
								{
									SIZE_T bytes;
									MmCopyVirtualMemory(tg_process, m->address, usermode_process, m->output, m->size, KernelMode, &bytes);
									//ReadProcessMemory(m->target_pid, m->address, m->output, m->size);
								}
							}
						}

					}
					else if (m->type == 11)
					{
						ULONG64 base_address;
						base_address = (ULONG64)GetProcessBaseAddress(m->target_pid);
						m->base_address = base_address;
					}
					else if (m->type == 12) {
						ULONG64 UB = handle_get_peb(m->target_pid);
						m->base_address = UB;
					}
					else if (m->type == 13) {
						ULONG64 UB = handle_get_peb1(m->target_pid);
						m->base_address = UB;
					}
					else if (m->type == 7)
					{
						//Write process memory
						if (!m->address || !m->size || !m->output || !m->target_pid || !m->usermode_pid) return STATUS_INVALID_PARAMETER_1;
						PEPROCESS usermode_process;
						if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->usermode_pid, &usermode_process)))
						{
							PEPROCESS tg_process;
							if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)m->target_pid, &tg_process)))
							{
								if (m->address > (void*)0x1000 && m->address < (void*)0x7FFFFFFEFFFF)
								{
									SIZE_T bytes;
									MmCopyVirtualMemory(usermode_process, m->output, tg_process, m->address, m->size, KernelMode, &bytes);
									//WriteProcessMemory(m->target_pid, m->address, m->output, m->size);
								}
							}
						}

					}
					/*else if (m->type == 8)
					{
						auto cr0 = __readcr0();
						const auto old_cr0 = cr0;
						// disable write protection
						cr0 &= ~(1UL << 16);
						__writecr0(cr0);
						m->output = (void*)0x1;

					}
					else if (m->type == 9)
					{
						//on wp bit
						auto cr0 = __readcr0();
						const auto old_cr0 = cr0;
						// disable write protection
						cr0 |= (1UL << 16);
						__writecr0(cr0);;
						m->output = (void*)0x2;
					}*/
					else if (m->type == 49) {
						m->output = (void*)IsClear;
					}
				}
				return -1;
			}
			
			return NtCompositionInputThread();
		}
	}
		
	return GreDxgkEnableUnorderedWaitsForDevice();
}
/// <summary>
/// Setups the hook.
/// </summary>
/// <returns></returns>
/// NtGdiPolyPolyDraw

bool SetupHook()
{
	PEPROCESS Target;
	NTSTATUS Status;

	if (NT_SUCCESS(Status = mem::FindProcessByName(skCrypt("explorer.exe"), &Target)))
	{
		//
		// Attaching on "explorer.exe"
		//

		KeAttachProcess(Target);

		//
		// The syscall that we're going to call in UM (NtGdiFlush)
		// 

		auto base = mem::GetSystemBaseModule(skCrypt("\\SystemRoot\\System32\\win32kbase.sys"));

		if (!base) {
			KeDetachProcess();
			return false;
		}
		//
		// First data pointer to use in our chain
		// 

		auto addr = FindPattern1(base, skCrypt("\x48\x85\xC0\x0F\x84\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x41\xBE\x00\x00\x00\x00"), skCrypt("xxxxx????xx????xx????"));
		addr = addr - 0x7;
		if (!addr)
		{
			DebugPrint("Yeah, totally Fucked up at addr\n");
			KeDetachProcess();
			return false;
		}

		NtCompositionInputThread_ret = (BYTE*)addr + 0x12;
		addr = RVA(addr, 7);

		//
		// Second data pointer to use in our chain (aka proxy)
		//

		void* pproxy = (void*)mem::GetSystemBaseModuleExport(skCrypt("\\SystemRoot\\System32\\win32kbase.sys"), skCrypt("GreDxgkRegisterDwmProcess"));
		if (!pproxy)
		{
			DebugPrint("Yeah, totally Fucked up at pproxy\n");
			KeDetachProcess();
			return false;
		}
		auto pdata2 = FindPattern1(base, skCrypt("\x48\x8B\x05\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\xCC\x83\x25\x00\x00\x00\x00\x00"), skCrypt("xxx????xx????xxxxxxxxxxxxxxxxx?????"));
		
		if (!pdata2)
		{
			DebugPrint("Yeah, totally Fucked up at pdata2\n");
			KeDetachProcess();
			return false;
		}


		pdata2 = RVA(pdata2, 7);

		//
		// Hook the proxy to our driver
		//

		*(void**)&GreDxgkEnableUnorderedWaitsForDevice = InterlockedExchangePointer((void**)pdata2, (void*)GreDxgkEnableUnorderedWaitsForDevice_hk);

		//
		// Hook nt to our proxy
		//

		*(void**)&NtCompositionInputThread = InterlockedExchangePointer((void**)addr, (void*)pproxy);

		// ..
		// Detach
		//

		KeDetachProcess();
	}
	else
	{
		return false;
	}
}

extern "C" NTSTATUS Main(uint64_t base, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	////DbgPrintEx(0, 0, "TEST");
	DebugPrint("maybe hook pro");
	if (SetupHook())
	{
		DebugPrint("maybe hook pro1");
		if (RemoveFromBigPool(base)) {
			DebugPrint("maybe hook pro2");
			if (RemovePfnDatabaseEntry(base)) {
				DebugPrint("maybe hook pro3");
				if (clearci()) {
					DebugPrint("maybe hook pro4");
					IsClear = 0x4747;
				}
				else {
				}
			}
			else {
			}
		}
		else {
		}
	}
	else {
	}
	return STATUS_SUCCESS;
}
