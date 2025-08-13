#include "disk.hpp"
#include "payloadbytes.h"
#include <intrin.h>


NTSTATUS PreparePayload(unsigned char* ImageBase, PVOID* buffer, UINT32 physicalPagesUsed, PHYSICAL_ADDRESS allocationBase, OUT PHYSICAL_ADDRESS* pdptPhysicalAddress, OUT UINT32* originalHookOffset, OUT UINT32* entryPoint)
{
	IMAGE_DOS_HEADER* dosHeaders = reinterpret_cast<IMAGE_DOS_HEADER*>(ImageBase);
	if (dosHeaders->e_magic != IMAGE_DOS_SIGNATURE)
	{
		DbgMsg("Invalid DOS signature: %04X", dosHeaders->e_magic);
		return NULL;
	}
	IMAGE_NT_HEADERS64* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(ImageBase + dosHeaders->e_lfanew);
	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
		return NULL;
	memcpy((PUINT8)(*buffer), ImageBase, ntHeaders->OptionalHeader.SizeOfHeaders);
	IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)((UINT8*)&ntHeaders->OptionalHeader + ntHeaders->FileHeader.SizeOfOptionalHeader);
	PHYSICAL_ADDRESS pdPhysicalBase{ };
	PHYSICAL_ADDRESS pdptPhysicalBase{ };
	PHYSICAL_ADDRESS ptPhysicalBase{ };
	for (UINT32 i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
	{
		IMAGE_SECTION_HEADER* section = &sections[i];
		if (section->SizeOfRawData)
		{
			memcpy
			(
				(PUINT8)(*buffer) + section->VirtualAddress,
				ImageBase + section->PointerToRawData,
				section->SizeOfRawData
			);
		}
		if (memcmp(section->Name, ".3", 2) == 0)
		{
			PDPTE_64* pdpt = reinterpret_cast<PDPTE_64*>((PUINT8)(*buffer) + section->VirtualAddress);
			pdpt[511].Present = 1;
			pdpt[511].PageFrameNumber = pdPhysicalBase.QuadPart >> 12;
			pdpt[511].Supervisor = 0;
			pdpt[511].Write = 1;
			pdptPhysicalBase.QuadPart = section->VirtualAddress + allocationBase.QuadPart;
			DbgMsg("Section .3 (pdpt) physical address at %p, pointing to physical %p", pdptPhysicalBase.QuadPart, pdPhysicalBase.QuadPart);
		}
		if (memcmp(section->Name, ".2", 2) == 0)
		{
			PDE_64* pd = reinterpret_cast<PDE_64*>((PUINT8)(*buffer) + section->VirtualAddress);
			pd[511].Present = 1;
			pd[511].PageFrameNumber = ptPhysicalBase.QuadPart >> 12;
			pd[511].Supervisor = 0;
			pd[511].Write = 1;
			pdPhysicalBase.QuadPart = section->VirtualAddress + allocationBase.QuadPart;
			DbgMsg("Section .2 (pd) physical address at %p, pointing to physical %p", pdPhysicalBase.QuadPart, ptPhysicalBase.QuadPart);
		}
		if (memcmp(section->Name, ".1", 2) == 0)
		{
			PTE_64* pt = reinterpret_cast<PTE_64*>((PUINT8)(*buffer) + section->VirtualAddress);
			for (UINT32 idx = 0; idx < physicalPagesUsed; idx++)
			{
				pt[idx].Present = 1;
				pt[idx].Supervisor = 0;
				pt[idx].Write = 1;

				UINT64 pagePhysicalAddress = allocationBase.QuadPart + idx * PAGE_SIZE;
				UINT64 pfn = pagePhysicalAddress >> 12;
				pt[idx].PageFrameNumber = pfn;
			}
			ptPhysicalBase.QuadPart = section->VirtualAddress + allocationBase.QuadPart;
			DbgMsg("Section .1 (pt) physical address at %p", ptPhysicalBase.QuadPart);
		}

	}

	IMAGE_EXPORT_DIRECTORY* ExportDir = (IMAGE_EXPORT_DIRECTORY*)(
		(PUINT8)(*buffer) + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	UINT32* Address = (UINT32*)((PUINT8)(*buffer) + ExportDir->AddressOfFunctions);
	UINT32* Name = (UINT32*)((PUINT8)(*buffer) + ExportDir->AddressOfNames);
	UINT16* Ordinal = (UINT16*)((PUINT8)(*buffer) + ExportDir->AddressOfNameOrdinals);

	for (UINT16 i = 0; i < ExportDir->AddressOfFunctions; i++)
	{
		if (strcmp((const char*)((PUINT8)(*buffer) + Name[i]), "OriginalOffsetFromHook"))
		{
			*originalHookOffset = Address[Ordinal[i]];
			break;
		}
	}

	IMAGE_DATA_DIRECTORY* baseRelocDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (baseRelocDir->VirtualAddress)
	{
		IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)((PUINT8)(*buffer) + baseRelocDir->VirtualAddress);
		for (UINT32 currentSize = 0; currentSize < baseRelocDir->Size; )
		{
			UINT32 relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(UINT16);
			UINT16* relocData = (UINT16*)((UINT8*)reloc + sizeof(IMAGE_BASE_RELOCATION));
			UINT8* relocBase = (PUINT8)(*buffer) + reloc->VirtualAddress;

			for (UINT32 i = 0; i < relocCount; ++i, ++relocData)
			{
				UINT16 data = *relocData;
				UINT16 type = data >> 12;
				UINT16 offset = data & 0xFFF;

				switch (type)
				{
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				case IMAGE_REL_BASED_DIR64:
				{
					UINT64* rva = (UINT64*)(relocBase + offset);
					*rva = (UINT64)((PUINT8)(*buffer) + (*rva - ntHeaders->OptionalHeader.ImageBase));
					break;
				}
				default:
					return STATUS_UNSUCCESSFUL;
				}
			}

			currentSize += reloc->SizeOfBlock;
			reloc = (IMAGE_BASE_RELOCATION*)relocData;
		}
	}
	*pdptPhysicalAddress = pdptPhysicalBase; 
	*entryPoint = ntHeaders->OptionalHeader.AddressOfEntryPoint;
	return STATUS_SUCCESS;
}

UINT32 PayLoadPageCount(VOID)
{
	IMAGE_DOS_HEADER* RecordDosImageHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(payloadData);
	if (RecordDosImageHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

    IMAGE_NT_HEADERS64* RecordNtHeaders = reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<UINT64>(RecordDosImageHeader) + RecordDosImageHeader->e_lfanew);
	if (RecordNtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	UINT32 imageSize = RecordNtHeaders->OptionalHeader.SizeOfImage;
	return (imageSize + 0xFFF) / 0x1000; 
}