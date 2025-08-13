#include "payload.hpp"
NTSTATUS ExecuteCPUIDEachProcessor()
{
    const ULONG numOfProcessors = KeQueryActiveProcessorCountEx(ALL_PROCESSOR_GROUPS);
    for (ULONG i = 0; i < numOfProcessors; i++)
    {
        PROCESSOR_NUMBER processorNumber;
        NTSTATUS status = KeGetProcessorNumberFromIndex(i, &processorNumber);
        if (!NT_SUCCESS(status))
            return status;

        GROUP_AFFINITY affinity;
        affinity.Group = processorNumber.Group;
        affinity.Mask = 1ULL << processorNumber.Number;
        affinity.Reserved[0] = affinity.Reserved[1] = affinity.Reserved[2] = 0;

        GROUP_AFFINITY oldAffinity;
        KeSetSystemGroupAffinityThread(&affinity, &oldAffinity);

        ExecuteCPUID();

        KeRevertToUserGroupAffinityThread(&oldAffinity);

        if (!NT_SUCCESS(status))
            return status;
    }

    return STATUS_SUCCESS;
}

void Sleep(int ms)
{
    LARGE_INTEGER interval;
    interval.QuadPart = -10 * 1000 * ms;
    KeDelayExecutionThread(KernelMode, FALSE, &interval);
}

BOOLEAN IsPageAllOnes(IN PVOID page) {
    for (UINT32 i = 0; i < PAGE_SIZE; i += sizeof(UINT64)) {
        if (*(PUINT64)((PUINT8)page + i) != MAXUINT64) {
            return FALSE;
        }
    }

    return TRUE;
}
static BOOLEAN ScanPattern(IN PVOID page, IN PUINT8 pattern, IN const char* mask, IN SIZE_T pattern_length, OUT PVOID* found_address) {
    for (UINT32 i = 0; i <= PAGE_SIZE - pattern_length; ++i) {
        PUINT8 ptr = (PUINT8)page + i;
        BOOLEAN match = TRUE;

        for (SIZE_T j = 0; j < pattern_length; ++j) {
            if (mask[j] == 'x' && ptr[j] != pattern[j]) {
                match = FALSE;
                break;
            }
        }

        if (match) {
            if (found_address) {
                *found_address = ptr;
            }
            return TRUE;
        }
    }
    return FALSE;
}

NTSTATUS FindContinuousEmptyPagesInRange(IN PPHYSICAL_MEMORY_RANGE range, IN PDISK disk, IN UINT64 numPages, OUT PVOID* bufferAddress, OUT PVOID* mappingOut, OUT PHYSICAL_ADDRESS* physicalAddress) {
    PVOID buffer = MmAllocateContiguousMemory(PAGE_SIZE * numPages, PHYSICAL_ADDRESS{ .QuadPart = MAXULONG32 });
    LONGLONG maxAddress = range->NumberOfBytes.QuadPart;
	LONGLONG baseAddress = range->BaseAddress.QuadPart;
    for (LONGLONG i = 0; i < maxAddress; i += PAGE_SIZE) {
        UINT64 pfn = (baseAddress + i) >> PAGE_SHIFT;

        MM_COPY_ADDRESS src;
        src.PhysicalAddress.QuadPart = pfn << PAGE_SHIFT;

        SIZE_T outSize;
        if (!NT_SUCCESS(MmCopyMemory(buffer, src, PAGE_SIZE * numPages, MM_COPY_MEMORY_PHYSICAL, &outSize))) {
            continue;
        }
        if (!IsPageAllOnes(buffer)) {
            continue;
        }
        PVOID mapping = MmMapIoSpace(src.PhysicalAddress, PAGE_SIZE * numPages, MmNonCached);
        if (!mapping) {
            continue;
        }

        if (!NT_SUCCESS(DiskCopyPages(disk, buffer, mapping, numPages))) {
            MmUnmapIoSpace(mapping, PAGE_SIZE * numPages);
            continue;
        }

        for (UINT32 j = 0; j < PAGE_SIZE * numPages; ++j) {
            PUINT8 ptr = (PUINT8)buffer + j;
            SIZE_T caveSize = 0;

            for (SIZE_T k = 0; (j + k) < PAGE_SIZE * numPages; ++k) {
                if (ptr[k] == 0x00 || ptr[k] == 0x90 || ptr[k] == 0xCC) {
                    caveSize++;
                }
                else {
                    break;
                }
            }
            if (caveSize >= PAGE_SIZE * numPages)
            {
                *physicalAddress = src.PhysicalAddress;
                *bufferAddress = (PUINT8)buffer;
                *mappingOut = mapping;
                return STATUS_SUCCESS;
            }
        }
		MmUnmapIoSpace(mapping, PAGE_SIZE * numPages);
    }
    return STATUS_UNSUCCESSFUL;
}