#pragma once
#include "imports.h"

namespace cleaner 
{
	PVOID g_KernelBase = NULL;
	ULONG g_KernelSize = 0;
	ERESOURCE PsLoadedModuleResource;

	typedef struct _RTL_PROCESS_MODULE_INFORMATION
	{
		HANDLE Section;
		PVOID MappedBase;
		PVOID ImageBase;
		ULONG ImageSize;
		ULONG Flags;
		USHORT LoadOrderIndex;
		USHORT InitOrderIndex;
		USHORT LoadCount;
		USHORT OffsetToFileName;
		UCHAR  FullPathName[256];
	} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

	typedef struct _RTL_PROCESS_MODULES
	{
		ULONG NumberOfModules;
		RTL_PROCESS_MODULE_INFORMATION Modules[1];
	} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

	BOOLEAN DataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
	{
		for (; *szMask; ++szMask, ++pData, ++bMask) if (*szMask == 'x' && *pData != *bMask) return 0;
		return (*szMask) == 0;
	}

	UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE* bMask, char* szMask)
	{
		for (UINT64 i = 0; i < dwLen; i++) if (DataCompare((BYTE*)(dwAddress + i), bMask, szMask)) return (UINT64)(dwAddress + i);
		return 0;
	}

	PVOID ResolveRelativeAddress(_In_ PVOID Instruction, _In_ ULONG OffsetOffset, _In_ ULONG InstructionSize)
	{
		ULONG_PTR Instr = (ULONG_PTR)Instruction;
		LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
		PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

		return ResolvedAddr;
	}
	NTSTATUS PatternScan(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound)
	{
		ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
		if (ppFound == NULL || pattern == NULL || base == NULL) return STATUS_INVALID_PARAMETER;

		for (ULONG_PTR i = 0; i < size - len; i++)
		{
			BOOLEAN found = TRUE;
			for (ULONG_PTR j = 0; j < len; j++)
			{
				if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
				{
					found = FALSE;
					break;
				}
			}
			if (found != FALSE)
			{
				*ppFound = (PUCHAR)base + i;
				return STATUS_SUCCESS;
			}
		}

		return STATUS_NOT_FOUND;
	}

	PVOID GetKernelBase(OUT PULONG pSize)
	{
		NTSTATUS status = STATUS_SUCCESS;
		ULONG bytes = 0;
		PRTL_PROCESS_MODULES pMods = NULL;
		PVOID checkPtr = NULL;
		UNICODE_STRING routineName;

		if (g_KernelBase != NULL)
		{
			if (pSize) *pSize = g_KernelSize;
			return g_KernelBase;
		}

		RtlUnicodeStringInit(&routineName, L"NtOpenFile");

		checkPtr = MmGetSystemRoutineAddress(&routineName);
		if (checkPtr == NULL) return NULL;

		status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

		if (bytes == 0) return NULL;

		pMods = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x504D5448);
		RtlZeroMemory(pMods, bytes);

		status = ZwQuerySystemInformation(SystemModuleInformation, pMods, bytes, &bytes);

		if (NT_SUCCESS(status))
		{
			PRTL_PROCESS_MODULE_INFORMATION pMod = pMods->Modules;
			for (ULONG i = 0; i < pMods->NumberOfModules; i++)
			{
				if (checkPtr >= pMod[i].ImageBase && checkPtr < (PVOID)((PUCHAR)pMod[i].ImageBase + pMod[i].ImageSize))
				{
					g_KernelBase = pMod[i].ImageBase;
					g_KernelSize = pMod[i].ImageSize;
					if (pSize) *pSize = g_KernelSize;
					break;
				}
			}
		}

		if (pMods) ExFreePoolWithTag(pMods, 0x504D5448);

		return g_KernelBase;
	}



}