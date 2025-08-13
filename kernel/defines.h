#pragma once
#include <ntifs.h>
#include <ntddscsi.h>
#include <intrin.h>
#pragma warning(disable: 4201 4996) // nonstandard extension used : nameless struct/union, ExAllocatePool deprication warning
extern "C" void LoaderASM();
extern "C" UINT64 ExecuteCPUID(...);
#define AMD_VMEXIT_HANDLER_SIG "\xE8\x00\x00\x00\x00\x48\x89\x04\x24\xE9"
#define AMD_VMEXIT_HANDLER_MASK "x????xxxxx"
#define CPUID_HV_VENDOR_LEAF (0x40000000)
#define DbgMsg(x, ...) DbgPrintEx(0, 0, x##"\n", __VA_ARGS__)
#define PAYLOAD_VIRTUAL_BASE (0x0000327FFFE00000)
typedef union
{
    struct
    {
        UINT64 Present : 1;
        UINT64 Write : 1;
        UINT64 Supervisor : 1;
        UINT64 PageLevelWriteThrough : 1;
        UINT64 PageLevelCacheDisable : 1;
        UINT64 Accessed : 1;
        UINT64 Reserved1 : 1;
        UINT64 LargePage : 1;
        UINT64 Ignored1 : 4;
        UINT64 PageFrameNumber : 40;
        UINT64 Ignored2 : 11;
        UINT64 ExecuteDisable : 1;
    };

    UINT64 Flags;
} PML4E_64;

typedef union
{
    struct
    {
        UINT64 Present : 1;
        UINT64 Write : 1;
        UINT64 Supervisor : 1;
        UINT64 PageLevelWriteThrough : 1;
        UINT64 PageLevelCacheDisable : 1;
        UINT64 Accessed : 1;
        UINT64 Reserved1 : 1;
        UINT64 LargePage : 1;
        UINT64 Ignored1 : 4;
        UINT64 PageFrameNumber : 40;
        UINT64 Ignored2 : 11;
        UINT64 ExecuteDisable : 1;
    };

    UINT64 Flags;
} PDPTE_64;
static_assert(sizeof(PDPTE_64) == 8, "size mismatch");


typedef union
{
    struct
    {
        UINT64 Present : 1;
        UINT64 Write : 1;
        UINT64 Supervisor : 1;
        UINT64 PageLevelWriteThrough : 1;
        UINT64 PageLevelCacheDisable : 1;
        UINT64 Accessed : 1;
        UINT64 Reserved1 : 1;
        UINT64 LargePage : 1;
        UINT64 Ignored1 : 4;
        UINT64 PageFrameNumber : 40;
        UINT64 Ignored2 : 11;
        UINT64 ExecuteDisable : 1;
    };

    UINT64 Flags;
} PDE_64;
static_assert(sizeof(PDE_64) == 8, "size mismatch");

typedef union
{
    struct
    {
        UINT64 Present : 1;
        UINT64 Write : 1;
        UINT64 Supervisor : 1;
        UINT64 PageLevelWriteThrough : 1;
        UINT64 PageLevelCacheDisable : 1;
        UINT64 Accessed : 1;
        UINT64 Dirty : 1;
        UINT64 Pat : 1;
        UINT64 Global : 1;
        UINT64 Avl : 3;
        UINT64 PageFrameNumber : 40;
        UINT64 Ignored2 : 7;
        UINT64 ProtectionKey : 4;
        UINT64 ExecuteDisable : 1;
    };

    UINT64 Flags;
} PTE_64;

typedef struct _DISK {
    PDEVICE_OBJECT Device;
    UINT8 Buffer[PAGE_SIZE];
} DISK, * PDISK;
#define SCSI_SECTOR_SIZE (0x200)
extern "C" POBJECT_TYPE* IoDriverObjectType;
extern "C" NTSTATUS ObReferenceObjectByName(IN PUNICODE_STRING objectName, IN ULONG attributes,
    IN PACCESS_STATE passedAccessState,
    IN ACCESS_MASK desiredAccess,
    IN POBJECT_TYPE objectType,
    IN KPROCESSOR_MODE accessMode,
    IN OUT PVOID parseContext, OUT PVOID* object);
typedef struct {
    SCSI_PASS_THROUGH_DIRECT spt;
    ULONG		Filler;
    UCHAR		ucSenseBuf[36];
} SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, * PSCSI_PASS_THROUGH_DIRECT_WITH_BUFFER;