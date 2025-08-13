//Mostly from https://github.com/SamuelTulach/SecureHack
#pragma once
#include "structs.h"
#define MAPPING_ADDRESS_BASE 0x0000327FFFC00000

#pragma section(".1", read, write)
__declspec(allocate(".1")) PTE_64 ImagePt[512];
#pragma section(".2", read, write)
__declspec(allocate(".2")) PDE_64 Pd[512];
#pragma section(".3", read, write)
__declspec(allocate(".3")) PDPTE_64 Pdpt[512];
#pragma section(".mappingpt", read, write)
__declspec(allocate(".mappingpt")) PTE_64 Pt[512];

static UINT64 currentPIDTracked = 0;
static UINT64 currentTrackedPdb = 0;
static UINT64 currentTrackedGS = 0;

PML4E_64* HyperVPml4 = (PML4E_64*)0xFFFFFF7FBFDFE000;
#define PAGE_MASK 0xFFF

#define SELF_REF_PML4_IDX 510
#define MAPPING_PML4_IDX 100

enum MapType
{
    MapSource,
    MapDestination
};

VOID* CopyMemory(VOID* dest, const VOID* src, const SIZE_T count)
{
    UINT8* d = (UINT8*)dest;
    const UINT8* s = (const UINT8*)src;

    for (SIZE_T i = 0; i < count; i++)
        d[i] = s[i];

    return dest;
}

UINT32 MemoryGetCoreIndex(VOID)
{
    CPUID_EAX_01 cpuidResult;
    __cpuid((INT32*)&cpuidResult, 1);
    return cpuidResult.ADDITIONAL_INFORMATION.INITIAL_APIC_ID;
}

UINT64 MemoryGetMapVirtual(UINT16 offset, enum MapType type)
{
    CPUID_EAX_01 cpuidResult;
    __cpuid((INT32*)&cpuidResult, 1);

    VIRTUAL_ADDRESS virtualAddress;
    virtualAddress.Value = MAPPING_ADDRESS_BASE;
    virtualAddress.PtIndex = MemoryGetCoreIndex() * 2 + (UINT32)type;
    return virtualAddress.Value + offset;
}


UINT64 MemoryMapPage(const UINT64 physicalAddress, const enum MapType type)
{
    CPUID_EAX_01 cpuidResult;
    __cpuid((INT32*)&cpuidResult, 1);

    const UINT32 index = MemoryGetCoreIndex() * 2 + (UINT32)type;
    Pt[index].PageFrameNumber = physicalAddress >> 12;

    const UINT64 mappedAddress = MemoryGetMapVirtual(physicalAddress & PAGE_MASK, type);
    __invlpg((void*)mappedAddress);

    return mappedAddress;
}
UINT64 MemoryTranslateGuestVirtual(const UINT64 directoryBase, const UINT64 guestVirtual, const enum MapType mapType)
{
    VIRTUAL_ADDRESS virtualAddress;
    virtualAddress.Value = guestVirtual;

    PML4E_64* pml4 = (PML4E_64*)MemoryMapPage(directoryBase, mapType);
    if (!pml4 || !pml4[virtualAddress.Pml4Index].Present)
        return 0;

    PDPTE_64* pdpt = (PDPTE_64*)MemoryMapPage(pml4[virtualAddress.Pml4Index].PageFrameNumber << 12, mapType);
    if (!pdpt || !pdpt[virtualAddress.PdptIndex].Present)
        return 0;

    // 1GB large page
    if (pdpt[virtualAddress.PdptIndex].LargePage)
        return (pdpt[virtualAddress.PdptIndex].PageFrameNumber << 12) + virtualAddress.Offset;

    PDE_64* pd = (PDE_64*)MemoryMapPage(pdpt[virtualAddress.PdptIndex].PageFrameNumber << 12, mapType);
    if (!pd || !pd[virtualAddress.PdIndex].Present)
        return 0;

    // 2MB large page
    if (pd[virtualAddress.PdIndex].LargePage)
        return (pd[virtualAddress.PdIndex].PageFrameNumber << 12) + virtualAddress.Offset;

    PTE_64* pt = (PTE_64*)MemoryMapPage(pd[virtualAddress.PdIndex].PageFrameNumber << 12, mapType);
    if (!pt || !pt[virtualAddress.PtIndex].Present)
        return 0;

    return (pt[virtualAddress.PtIndex].PageFrameNumber << 12) + virtualAddress.Offset;
}

UINT64 MemoryMapGuestVirtual(const UINT64 directoryBase, const UINT64 virtualAddress, const enum MapType mapType)
{
    const UINT64 guestPhysical = MemoryTranslateGuestVirtual(directoryBase, virtualAddress, mapType);
    if (!guestPhysical)
        return 0;

    return MemoryMapPage(guestPhysical, mapType);
}
UINT64 MemoryTranslate(const UINT64 hostVirtual)
{
    VIRTUAL_ADDRESS virtualAddress;
    virtualAddress.Value = hostVirtual;

    VIRTUAL_ADDRESS cursor;
    cursor.Value = (UINT64)HyperVPml4;

    if (!((PML4E_64*)cursor.Pointer)[virtualAddress.Pml4Index].Present)
        return 0;

    cursor.PtIndex = virtualAddress.Pml4Index;
    if (!((PDPTE_64*)cursor.Pointer)[virtualAddress.PdptIndex].Present)
        return 0;

    // 1GB large page
    if (((PDPTE_64*)cursor.Pointer)[virtualAddress.PdptIndex].LargePage)
        return (((PDPTE_64*)cursor.Pointer)[virtualAddress.PdptIndex].PageFrameNumber << 30) + virtualAddress.Offset;

    cursor.PdIndex = virtualAddress.Pml4Index;
    cursor.PtIndex = virtualAddress.PdptIndex;
    if (!((PDE_64*)cursor.Pointer)[virtualAddress.PdIndex].Present)
        return 0;

    // 2MB large page
    if (((PDE_64*)cursor.Pointer)[virtualAddress.PdIndex].LargePage)
        return (((PDE_64*)cursor.Pointer)[virtualAddress.PdIndex].PageFrameNumber << 21) + virtualAddress.Offset;

    cursor.PdptIndex = virtualAddress.Pml4Index;
    cursor.PdIndex = virtualAddress.PdptIndex;
    cursor.PtIndex = virtualAddress.PdIndex;
    if (!((PTE_64*)cursor.Pointer)[virtualAddress.PtIndex].Present)
        return 0;

    return (((PTE_64*)cursor.Pointer)[virtualAddress.PtIndex].PageFrameNumber << 12) + virtualAddress.Offset;
}
bool MemoryInit()
{
    //Must be run on each core
    UINT64 PtPhysical = MemoryTranslate((UINT64)Pt);
    UINT64 PdptPhysical = MemoryTranslate((UINT64)Pdpt);
    Pd[510].Present = 1;
    Pd[510].PageFrameNumber = PtPhysical >> 12;
    Pd[510].Supervisor = 0;
    Pd[510].Write = 1;

    for (UINT32 idx = 0; idx < 512; idx++)
    {
        Pt[idx].Present = 1;
        Pt[idx].Supervisor = 0;
        Pt[idx].Write = 1;
    }

    __wbinvd();
    PML4E_64* mappedPml4 = (PML4E_64*)MemoryMapPage(__readcr3(), MapSource);
    const UINT64 translated = MemoryTranslate((UINT64)mappedPml4);
    if (translated != __readcr3())
        return false;

    if (mappedPml4[SELF_REF_PML4_IDX].PageFrameNumber != (__readcr3() >> 12))
        return false;

    if (mappedPml4[MAPPING_PML4_IDX].PageFrameNumber != (PdptPhysical >> 12))
        return false;

    return true;
}
bool MemoryReadPhysical(UINT64 physicalSource, UINT64 cr3Destination, UINT64 virtualDestination, UINT64 size)
{
    while (size)
    {
        UINT64 destSize = PAGE_SIZE - (virtualDestination & PAGE_MASK);
        if (size < destSize)
            destSize = size;

        UINT64 srcSize = PAGE_SIZE - (physicalSource & PAGE_MASK);
        if (size < srcSize)
            srcSize = size;

        VOID* mappedSrc = (VOID*)MemoryMapPage(physicalSource, MapSource);
        if (!mappedSrc)
            return false;

        VOID* mappedDest = (VOID*)MemoryMapGuestVirtual(cr3Destination, virtualDestination, MapDestination);
        if (!mappedDest)
            return false;

        const UINT64 currentSize = (destSize < srcSize) ? destSize : srcSize;
        CopyMemory(mappedDest, mappedSrc, currentSize);

        physicalSource += currentSize;
        virtualDestination += currentSize;
        size -= currentSize;
    }

    return true;
}

int MemoryCopyGuestVirtual(const UINT64 dirbaseSource, UINT64 virtualSource, const UINT64 dirbaseDestination, UINT64 virtualDestination, UINT64 size)
{
    while (size)
    {
        UINT64 destSize = PAGE_SIZE - (virtualDestination & PAGE_MASK);
        if (size < destSize)
            destSize = size;

        UINT64 srcSize = PAGE_SIZE - (virtualSource & PAGE_MASK);
        if (size < srcSize)
            srcSize = size;

        VOID* mappedSrc = (VOID*)MemoryMapGuestVirtual(dirbaseSource, virtualSource, MapSource);
        if (!mappedSrc)
            return 2;

        VOID* mappedDest = (VOID*)MemoryMapGuestVirtual(dirbaseDestination, virtualDestination, MapDestination);
        if (!mappedDest)
            return 3;

        const UINT64 currentSize = (destSize < srcSize) ? destSize : srcSize;
        CopyMemory(mappedDest, mappedSrc, currentSize);

        virtualSource += currentSize;
        virtualDestination += currentSize;
        size -= currentSize;
    }

    return true;
}

template <typename T>
const T Read(const UINT64 address, const UINT64 sourceCr3) noexcept
{
    T value = { };
	MemoryCopyGuestVirtual(sourceCr3, address, __readcr3(), reinterpret_cast<UINT64>(&value), sizeof(T));
    return value;
}

void Read(const UINT64 address, const UINT64 sourceCr3, OUT void* buffer, const UINT64 size) noexcept
{
    if (size == 0)
        return;
    MemoryCopyGuestVirtual(sourceCr3, address, __readcr3(), reinterpret_cast<UINT64>(buffer), size);
}

// Write process memory
template <typename T>
void Write(const UINT64 address, const T& value, const UINT64 destCr3) noexcept
{
    MemoryCopyGuestVirtual(__readcr3(), reinterpret_cast<UINT64>(&value), destCr3, address, sizeof(T));
}

UINT64 MemoryGetModuleOfTracked(wchar_t moduleName[64], OUT PUINT64 baseAddress, OUT PUINT64 size)
{
    if (currentTrackedGS == 0 || currentTrackedPdb == 0)
        return false;

    UINT64 pebAddress = Read<UINT64>(currentTrackedGS + 0x60, currentTrackedPdb);
    PEB peb = Read<PEB>(pebAddress, currentTrackedPdb);
    PEB_LDR_DATA ldr = Read<PEB_LDR_DATA>((UINT64)peb.Ldr, currentTrackedPdb);

    UINT64 listHeadAddr = (UINT64)peb.Ldr + offsetof(PEB_LDR_DATA, InLoadOrderModuleList);
    LIST_ENTRY head = Read<LIST_ENTRY>(listHeadAddr, currentTrackedPdb);
    UINT64 currEntryAddr = reinterpret_cast<UINT64>(head.Flink);
    int maxIterations = 512;



    while (currEntryAddr != listHeadAddr && maxIterations--) {
        LDR_DATA_TABLE_ENTRY entry = Read<LDR_DATA_TABLE_ENTRY>(currEntryAddr, currentTrackedPdb);
        UNICODE_STRING baseName = entry.BaseDllName; 
        if (!baseName.Buffer || baseName.Length == 0)
        {
            currEntryAddr = reinterpret_cast<UINT64>(entry.InLoadOrderLinks.Flink);
			continue;
        }
        wchar_t nameBuf[64] = {};
        Read((UINT64)baseName.Buffer, currentTrackedPdb, nameBuf, baseName.Length);
        if (memcmp(nameBuf, moduleName, 63) == 0) {
            if (baseAddress) *baseAddress = reinterpret_cast<UINT64>(entry.DllBase);
            if (size) *size = entry.SizeOfImage;
            return true;
        }
        currEntryAddr = reinterpret_cast<UINT64>(entry.InLoadOrderLinks.Flink);
    }

	*baseAddress = 0;
	*size = 0;

    return false;
}
