#pragma once
#include <ntdef.h>
typedef struct
{
    UINT64 Low;
    UINT64 High;
} UINT128;
typedef struct __declspec(align(16)) GUEST_CONTEXT
{
    UINT8 Reserved1[8];
    UINT64 Rcx;
    UINT64 Rdx;
    UINT64 Rbx;
    UINT8 Reserved2[8];
    UINT64 Rbp;
    UINT64 Rsi;
    UINT64 Rdi;
    UINT64 R8;
    UINT64 R9;
    UINT64 R10;
    UINT64 R11;
    UINT64 R12;
    UINT64 R13;
    UINT64 R14;
    UINT64 R15;
    UINT128 Xmm0;
    UINT128 Xmm1;
    UINT128 Xmm2;
    UINT128 Xmm3;
    UINT128 Xmm4;
    UINT128 Xmm5;
    UINT128 Xmm6;
    UINT128 Xmm7;
    UINT128 Xmm8;
    UINT128 Xmm9;
    UINT128 Xmm10;
    UINT128 Xmm11;
    UINT128 Xmm12;
    UINT128 Xmm13;
    UINT128 Xmm14;
    UINT128 Xmm15;
    UINT8 Reserved3[8];
    UINT64 VmcbPhysicalAddress;
} GUEST_CONTEXT, * PGUEST_CONTEXT;
__declspec(dllexport) inline INT64 OriginalOffsetFromHook = 0x0;
typedef UINT64(*OriginalVmExitHandler_t)(VOID* arg1, VOID* arg2, PGUEST_CONTEXT context);
PVMCB_CONTROL_AREA GetVmcb(const UINT64 context)
{
    //const UINT64 v2 = *((UINT64*)context - 280);
    //return *(PVMCB_CONTROL_AREA*)(v2 + 3712);
    UINT64 v3 = *((UINT64*)context - 392);
    return **(PVMCB_CONTROL_AREA**)(v3 + 5056);
}
