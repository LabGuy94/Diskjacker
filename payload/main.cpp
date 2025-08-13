//Mostly from https://github.com/SamuelTulach/SecureHack
#include <xmmintrin.h>
#include <ntdef.h>
#include <intrin.h>
#include "shared.hpp"
#include "svm.hpp"
#include "hyperv.hpp"
#include "memory.hpp"
extern "C" void JmpToOriginal(void* arg1, void* arg2, const PGUEST_CONTEXT context, UINT64 toJmp);
COMMAND_DATA GetCommand(const PVMCB_CONTROL_AREA vmcb, const PGUEST_CONTEXT context)
{
    CR3 cr3;
    cr3.AsUInt = vmcb->Cr3;

    const UINT64 directoryBase = cr3.AddressOfPageDirectory << 12;
    const UINT64 commandPage = MemoryMapGuestVirtual(directoryBase, context->R8, MapSource);

    return *(COMMAND_DATA*)commandPage;
}

VOID SetCommand(const PVMCB_CONTROL_AREA vmcb, const PGUEST_CONTEXT context, COMMAND_DATA* data)
{
    CR3 cr3;
    cr3.AsUInt = vmcb->Cr3;

    const UINT64 directoryBase = cr3.AddressOfPageDirectory << 12;
    const UINT64 commandPage = MemoryMapGuestVirtual(directoryBase, context->R8, MapSource);

    *(COMMAND_DATA*)commandPage = *data;
}
VOID CommandHandler(const PVMCB_CONTROL_AREA vmcb, const PGUEST_CONTEXT context)
{
    switch (context->Rdx)
    {
        case COMMAND_CHECK_PRESENCE:
            vmcb->Rax = CPUID_RETURN_VALUE;
            break;
        case COMMAND_INIT_MEMORY:
            vmcb->Rax = MemoryInit();
            break;
        case COMMAND_GET_CR3:
            vmcb->Rax = vmcb->Cr3;
            break;
        case COMMAND_SET_PID_CR3:
            currentPIDTracked = context->R8;
            currentTrackedPdb = 0;
            currentTrackedGS = 0;
            break;
        case COMMAND_GET_MODULE_INFO:
            GET_MODULE_INFO getModuleInfoCommand = GetCommand(vmcb, context).GetModuleInfo;
            vmcb->Rax = MemoryGetModuleOfTracked(getModuleInfoCommand.ModuleName, &getModuleInfoCommand.ModuleBaseAddress, &getModuleInfoCommand.ModuleSize);
            COMMAND_DATA updatedCommandData;
            updatedCommandData.GetModuleInfo = getModuleInfoCommand;
            SetCommand(vmcb, context, &updatedCommandData);
            break;
        case COMMAND_GET_CR3_PID:
            vmcb->Rax = currentTrackedPdb;
			break;
        case COMMAND_READ_PHYSICAL:
            READ_PHYSICAL readPhysicalCommand = GetCommand(vmcb, context).ReadPhysical;
            vmcb->Rax = MemoryReadPhysical(readPhysicalCommand.PhysicalSourceAddress, readPhysicalCommand.Cr3 == 0 ? vmcb->Cr3 : readPhysicalCommand.Cr3, readPhysicalCommand.VirtualDestinationAddress, readPhysicalCommand.Size);
            break;
        case COMMAND_VIRTUAL_MEMORY_COPY:
			VIRTUAL_MEMORY_COPY virtualMemoryCopyCommand = GetCommand(vmcb, context).VirtualMemoryCopy;
			vmcb->Rax = MemoryCopyGuestVirtual(
                virtualMemoryCopyCommand.SourceCr3 == 0 ? (virtualMemoryCopyCommand.isWrite ? vmcb->Cr3 : currentTrackedPdb) : virtualMemoryCopyCommand.SourceCr3,
                virtualMemoryCopyCommand.SourceAddress, 
                virtualMemoryCopyCommand.DestinationCr3 == 0 ? (virtualMemoryCopyCommand.isWrite ? currentTrackedPdb : vmcb->Cr3) : virtualMemoryCopyCommand.DestinationCr3,
                virtualMemoryCopyCommand.DestinationAddress, 
                virtualMemoryCopyCommand.Size
            );
            break;
    }
}

void trackPDB(PVMCB_CONTROL_AREA vmcb)
{
    if (currentPIDTracked != 0 && currentTrackedPdb == 0 && (vmcb->CsSelector & 0x3) == 3 && vmcb->GsBase != 0 && MemoryTranslateGuestVirtual(vmcb->Cr3, vmcb->GsBase + 0x40, MapSource) != 0)
    {
        ULONGLONG pid = 0;
        MemoryCopyGuestVirtual(
            vmcb->Cr3,
            vmcb->GsBase + 0x40,
            __readcr3(),
            reinterpret_cast<UINT64>(&pid),
            sizeof(ULONGLONG)
        );
        if (pid == currentPIDTracked)
        {
            CR3 cr3;
            cr3.AsUInt = vmcb->Cr3;
            currentTrackedPdb = cr3.AddressOfPageDirectory << 12;
            currentTrackedGS = vmcb->GsBase;
        }
    }
}

typedef void(*JmpToOriginal_t)(void* arg1, void* arg2, const PGUEST_CONTEXT context, UINT64 jmpTarget);
UINT64 VmExitHandler(void* arg1, void* arg2, const PGUEST_CONTEXT context)
{
    PVMCB_CONTROL_AREA vmcb = GetVmcb((UINT64)arg2);
    trackPDB(vmcb);
    if (vmcb->ExitCode == VMEXIT_CPUID && context->Rcx == CPUID_BACKDOOR)
    {
        CommandHandler(vmcb, context);
        vmcb->Rip = vmcb->NRip;
        return __readgsqword(0);
    }
    JmpToOriginal(arg1, arg2, context, OriginalOffsetFromHook);
    __assume(0);
}