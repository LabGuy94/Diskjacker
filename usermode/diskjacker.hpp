#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include "shared.hpp"
#include <Windows.h>
#include <tlhelp32.h>
#include <string>

namespace memory
{
	extern "C" UINT64 ExecuteCPUID(...);
	bool isHijacked()
	{
		return ExecuteCPUID(CPUID_BACKDOOR, COMMAND_CHECK_PRESENCE) == CPUID_RETURN_VALUE;
	}
    inline DWORD getPIDByName(const std::wstring& processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return 0;
        }

        PROCESSENTRY32W pe;
        pe.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(hSnapshot, &pe)) {
            CloseHandle(hSnapshot);
            return 0;
        }

        do {
            if (processName == pe.szExeFile) {
                CloseHandle(hSnapshot);
                return pe.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe));

        CloseHandle(hSnapshot);
        return 0;
    }
    inline bool init()
    {
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);

        for (DWORD_PTR core = 0; core < sysInfo.dwNumberOfProcessors; ++core)
        {
            const DWORD_PTR affinityMask = 1ULL << core;
            const HANDLE currentThread = GetCurrentThread();
            const DWORD_PTR previousAffinityMask = SetThreadAffinityMask(currentThread, affinityMask);

            if (!previousAffinityMask)
                continue;

            const UINT64 status = ExecuteCPUID(CPUID_BACKDOOR, COMMAND_INIT_MEMORY);
            if (status == false)
            {
                SetThreadAffinityMask(currentThread, previousAffinityMask);
                return false;
            }

            SetThreadAffinityMask(currentThread, previousAffinityMask);
        }

        return true;
    }

    inline UINT64 getCR3()
    {
        return ExecuteCPUID(CPUID_BACKDOOR, COMMAND_GET_CR3);
    }

    inline UINT64 readPhysical(UINT64 physicalAddress, UINT64 buffer, UINT64 size, UINT64 cr3 = 0)
    {
        COMMAND_DATA data;
        data.ReadPhysical.Size = size;
        data.ReadPhysical.PhysicalSourceAddress = physicalAddress;
        data.ReadPhysical.Cr3 = cr3;
        data.ReadPhysical.VirtualDestinationAddress = buffer;
        return ExecuteCPUID(CPUID_BACKDOOR, COMMAND_READ_PHYSICAL, &data);
    }

    inline UINT64 readVirtual(UINT64 virtualAddress, UINT64 buffer, UINT64 size, UINT64 targetCr3 = 0)
    {
        COMMAND_DATA data;
        data.VirtualMemoryCopy.Size = size;
        data.VirtualMemoryCopy.SourceAddress = virtualAddress;
        data.VirtualMemoryCopy.SourceCr3 = targetCr3;
        data.VirtualMemoryCopy.DestinationCr3 = 0;
        data.VirtualMemoryCopy.DestinationAddress = buffer;
        data.VirtualMemoryCopy.isWrite = false;
        return ExecuteCPUID(CPUID_BACKDOOR, COMMAND_VIRTUAL_MEMORY_COPY, &data);
	}

    inline UINT64 writeVirtual(UINT64 virtualAddress, UINT64 buffer, UINT64 size, UINT64 targetCr3 = 0)
    {
        COMMAND_DATA data;
        data.VirtualMemoryCopy.Size = size;
        data.VirtualMemoryCopy.DestinationAddress = virtualAddress;
        data.VirtualMemoryCopy.DestinationCr3 = targetCr3;
		data.VirtualMemoryCopy.SourceCr3 = 0;
        data.VirtualMemoryCopy.SourceAddress = buffer;
        data.VirtualMemoryCopy.isWrite = true;
        return ExecuteCPUID(CPUID_BACKDOOR, COMMAND_VIRTUAL_MEMORY_COPY, &data);
    }

    inline GET_MODULE_INFO getModuleInfo(const std::wstring& moduleName)
    {
        COMMAND_DATA data;
        wcsncpy(data.GetModuleInfo.ModuleName, moduleName.c_str(), sizeof(data.GetModuleInfo.ModuleName) / sizeof(wchar_t) - 1);
        ExecuteCPUID(CPUID_BACKDOOR, COMMAND_GET_MODULE_INFO, &data);
		return data.GetModuleInfo;
	}

    template <typename T>
    const T Read(const std::uintptr_t address) noexcept
    {
        T value = { };
		readVirtual(address, reinterpret_cast<UINT64>(&value), sizeof(T));
        return value;
    }

    template <typename T>
    void Write(const std::uintptr_t address, const T& value) noexcept
    {
		writeVirtual(address, reinterpret_cast<UINT64>(&value), sizeof(T));
    }

    inline UINT64 setTrackedProcessPID(UINT32 pid)
    {
        return ExecuteCPUID(CPUID_BACKDOOR, COMMAND_SET_PID_CR3, pid);
	}
    inline UINT64 setTrackedProcessName(const std::wstring& processName)
    {
		return setTrackedProcessPID(getPIDByName(processName));
    }
    inline UINT64 getTrackedPDB()
    {
        return ExecuteCPUID(CPUID_BACKDOOR, COMMAND_GET_CR3_PID);
	}
}