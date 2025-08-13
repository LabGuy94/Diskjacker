#pragma once
#include <ntdef.h>
#include <wdm.h>
#include <ntddk.h>
#pragma warning(disable: 4201) // nonstandard extension used : nameless struct/union
#pragma pack(push, 1)
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
typedef union VIRT_ADDR_
{
    UINT64 Value;
    void* Pointer;
    struct
    {
        UINT64 Offset : 12;
        UINT64 PtIndex : 9;
        UINT64 PdIndex : 9;
        UINT64 PdptIndex : 9;
        UINT64 Pml4Index : 9;
        UINT64 Reserved : 16;
    };
} VIRTUAL_ADDRESS;

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
typedef union
{
    struct
    {
        UINT64 Reserved1 : 3;

        /**
         * @brief Page-level Write-Through
         *
         * [Bit 3] Controls the memory type used to access the first paging structure of the
         * current paging-structure hierarchy. This bit is not used if paging is disabled,
         * with PAE paging, or with 4-level paging if CR4.PCIDE=1.
         *
         * @see Vol3A[4.9(PAGING AND MEMORY TYPING)]
         */
        UINT64 PageLevelWriteThrough : 1;
#define CR3_PAGE_LEVEL_WRITE_THROUGH_BIT  3
#define CR3_PAGE_LEVEL_WRITE_THROUGH_FLAG 0x08
#define CR3_PAGE_LEVEL_WRITE_THROUGH_MASK 0x01
#define CR3_PAGE_LEVEL_WRITE_THROUGH(_)   (((_) >> 3) & 0x01)

        /**
         * @brief Page-level Cache Disable
         *
         * [Bit 4] Controls the memory type used to access the first paging structure of the
         * current paging-structure hierarchy. This bit is not used if paging is disabled,
         * with PAE paging, or with 4-level paging2 if CR4.PCIDE=1.
         *
         * @see Vol3A[4.9(PAGING AND MEMORY TYPING)]
         */
        UINT64 PageLevelCacheDisable : 1;
#define CR3_PAGE_LEVEL_CACHE_DISABLE_BIT  4
#define CR3_PAGE_LEVEL_CACHE_DISABLE_FLAG 0x10
#define CR3_PAGE_LEVEL_CACHE_DISABLE_MASK 0x01
#define CR3_PAGE_LEVEL_CACHE_DISABLE(_)   (((_) >> 4) & 0x01)
        UINT64 Reserved2 : 7;

        /**
         * @brief Address of page directory
         *
         * [Bits 47:12] Physical address of the 4-KByte aligned page directory (32-bit
         * paging) or PML4 table (64-bit paging) used for linear-address translation.
         *
         * @see Vol3A[4.3(32-BIT PAGING)]
         * @see Vol3A[4.5(4-LEVEL PAGING)]
         */
        UINT64 AddressOfPageDirectory : 36;
#define CR3_ADDRESS_OF_PAGE_DIRECTORY_BIT  12
#define CR3_ADDRESS_OF_PAGE_DIRECTORY_FLAG 0xFFFFFFFFF000
#define CR3_ADDRESS_OF_PAGE_DIRECTORY_MASK 0xFFFFFFFFF
#define CR3_ADDRESS_OF_PAGE_DIRECTORY(_)   (((_) >> 12) & 0xFFFFFFFFF)
        UINT64 Reserved3 : 16;
    };

    UINT64 AsUInt;
} CR3;
static_assert(sizeof(PTE_64) == 8, "size mismatch");
#pragma pack(pop)
struct CPUID_EAX_01
{
    union
    {
        struct
        {
            INT cpu_info[4];
        };

        struct
        {
            UINT32 EAX;
            UINT32 EBX;
            UINT32 ECX;
            UINT32 EDX;
        };

        struct
        {
            union
            {
                UINT32 FLAGS;

                struct
                {
                    UINT32 STEPPING_ID : 4;
                    UINT32 MODEL : 4;
                    UINT32 FAMILY_ID : 4;
                    UINT32 PROCESSOR_TYPE : 2;
                    UINT32 RESERVED1 : 2;
                    UINT32 EXTENDED_MODEL_ID : 4;
                    UINT32 EXTENDED_FAMILY_ID : 8;
                    UINT32 RESERVED2 : 4;
                };
            } VERSION_INFORMATION;

            union
            {
                UINT32 FLAGS;

                struct
                {
                    UINT32 BRAND_INDEX : 8;
                    UINT32 CLFLUSH_LINE_SIZE : 8;
                    UINT32 MAX_ADDRESSABLE_IDS : 8;
                    UINT32 INITIAL_APIC_ID : 8;
                };
            } ADDITIONAL_INFORMATION;

            union
            {
                UINT32 FLAGS;

                struct
                {
                    UINT32 SSE3 : 1;
                    UINT32 PCLMULQDQ : 1;
                    UINT32 DTES64 : 1;
                    UINT32 MONITOR : 1;
                    UINT32 DS_CPL : 1;
                    UINT32 VMX : 1;
                    UINT32 SMX : 1;
                    UINT32 EIST : 1;
                    UINT32 TM2 : 1;
                    UINT32 SSSE3 : 1;
                    UINT32 CNXT_ID : 1;
                    UINT32 SDBG : 1;
                    UINT32 FMA : 1;
                    UINT32 CMPXCHG16B : 1;
                    UINT32 XTPR : 1;
                    UINT32 PDCM : 1;
                    UINT32 RESERVED1 : 1;
                    UINT32 PCID : 1;
                    UINT32 DCA : 1;
                    UINT32 SSE4_1 : 1;
                    UINT32 SSE4_2 : 1;
                    UINT32 X2APIC : 1;
                    UINT32 MOVBE : 1;
                    UINT32 POPCNT : 1;
                    UINT32 TSC_DEADLINE : 1;
                    UINT32 AESNI : 1;
                    UINT32 XSAVE : 1;
                    UINT32 OSXSAVE : 1;
                    UINT32 AVX : 1;
                    UINT32 F16C : 1;
                    UINT32 RDRAND : 1;
                    UINT32 RESERVED2 : 1;
                };
            } FEATURE_INFORMATION_ECX;

            union
            {
                UINT32 FLAGS;

                struct
                {
                    UINT32 FPU : 1;
                    UINT32 VME : 1;
                    UINT32 DE : 1;
                    UINT32 PSE : 1;
                    UINT32 TSC : 1;
                    UINT32 MSR : 1;
                    UINT32 PAE : 1;
                    UINT32 MCE : 1;
                    UINT32 CX8 : 1;
                    UINT32 APIC : 1;
                    UINT32 RESERVED1 : 1;
                    UINT32 SEP : 1;
                    UINT32 MTRR : 1;
                    UINT32 PGE : 1;
                    UINT32 MCA : 1;
                    UINT32 CMOV : 1;
                    UINT32 PAT : 1;
                    UINT32 PSE36 : 1;
                    UINT32 PSN : 1;
                    UINT32 CLFSH : 1;
                    UINT32 RESERVED2 : 1;
                    UINT32 DS : 1;
                    UINT32 ACPI : 1;
                    UINT32 MMX : 1;
                    UINT32 FXSR : 1;
                    UINT32 SSE : 1;
                    UINT32 SSE2 : 1;
                    UINT32 SS : 1;
                    UINT32 HTT : 1;
                    UINT32 TM : 1;
                    UINT32 RESERVED3 : 1;
                    UINT32 PBE : 1;
                };
            } FEATURE_INFORMATION_EDX;
        };
    };
};
typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union
    {
        LIST_ENTRY HashLinks;
        PVOID SectionPointer;
    };
    ULONG CheckSum;
    union
    {
        ULONG TimeDateStamp;
        PVOID LoadedImports;
    };
    PVOID EntryPointActivationContext;
    PVOID PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _RTL_CRITICAL_SECTION_DEBUG
{
    UINT16   Type;
    UINT16   CreatorBackTraceIndex;
    struct _RTL_CRITICAL_SECTION* CriticalSection;
    LIST_ENTRY ProcessLocksList;
    UINT32 EntryCount;
    UINT32 ContentionCount;
    UINT32 Spare[2];
} RTL_CRITICAL_SECTION_DEBUG, * PRTL_CRITICAL_SECTION_DEBUG, RTL_RESOURCE_DEBUG, * PRTL_RESOURCE_DEBUG;


typedef struct _RTL_CRITICAL_SECTION {
    PRTL_CRITICAL_SECTION_DEBUG DebugInfo;
    LONG LockCount;
    LONG RecursionCount;
    HANDLE OwningThread;
    HANDLE LockSemaphore;
    ULONG_PTR SpinCount;
}  RTL_CRITICAL_SECTION, * PRTL_CRITICAL_SECTION;
typedef struct _CURDIR
{
    UNICODE_STRING DosPath;
    HANDLE Handle;
} CURDIR, * PCURDIR;
typedef struct _RTL_DRIVE_LETTER_CURDIR
{
    USHORT Flags;
    USHORT Length;
    ULONG TimeStamp;
    UNICODE_STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;
typedef struct _RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;
    ULONG Length;

    ULONG Flags;
    ULONG DebugFlags;

    HANDLE ConsoleHandle;
    ULONG ConsoleFlags;
    HANDLE StandardInput;
    HANDLE StandardOutput;
    HANDLE StandardError;

    CURDIR CurrentDirectory;
    UNICODE_STRING DllPath;
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
    PWCHAR Environment;

    ULONG StartingX;
    ULONG StartingY;
    ULONG CountX;
    ULONG CountY;
    ULONG CountCharsX;
    ULONG CountCharsY;
    ULONG FillAttribute;

    ULONG WindowFlags;
    ULONG ShowWindowFlags;
    UNICODE_STRING WindowTitle;
    UNICODE_STRING DesktopInfo;
    UNICODE_STRING ShellInfo;
    UNICODE_STRING RuntimeData;
    RTL_DRIVE_LETTER_CURDIR CurrentDirectories[32];

    ULONG_PTR EnvironmentSize;
    ULONG_PTR EnvironmentVersion;
    PVOID PackageDependencyData;
    ULONG ProcessGroupId;
    ULONG LoaderThreads;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
    PVOID EntryInProgress;
    BOOLEAN ShutdownInProgress;
    HANDLE ShutdownThreadId;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsLegacyProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN SpareBits : 3;
        };
    };
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
} PEB, * PPEB;