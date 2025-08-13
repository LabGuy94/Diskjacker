#pragma once
#include <basetsd.h>
#define CPUID_BACKDOOR 0xDEAD
#define CPUID_RETURN_VALUE 0x123456789

#define COMMAND_CHECK_PRESENCE 1
#define COMMAND_INIT_MEMORY 2
#define COMMAND_GET_CR3 3
#define COMMAND_READ_PHYSICAL 4
#define COMMAND_VIRTUAL_MEMORY_COPY 5
#define COMMAND_GET_CR3_PID 6
#define COMMAND_SET_PID_CR3 7
#define COMMAND_GET_MODULE_INFO 8
typedef struct _READ_PHYSICAL
{
    UINT64 PhysicalSourceAddress;
    UINT64 VirtualDestinationAddress;
    UINT64 Cr3;
    UINT64 Size;
} READ_PHYSICAL;
typedef struct _GET_MODULE_INFO
{
	wchar_t ModuleName[64]; 
    UINT64 ModuleBaseAddress;
    UINT64 ModuleSize;
} GET_MODULE_INFO;
typedef struct _VIRTUAL_MEMORY_COPY
{
    UINT64 SourceCr3;
    UINT64 SourceAddress;
    UINT64 DestinationCr3;
    UINT64 DestinationAddress;
    UINT64 Size;
    bool isWrite;
} VIRTUAL_MEMORY_COPY;
typedef struct COMMAND_DATA
{
    union
    {
        READ_PHYSICAL ReadPhysical;
        VIRTUAL_MEMORY_COPY VirtualMemoryCopy;
        GET_MODULE_INFO GetModuleInfo;
    };
} COMMAND_DATA;