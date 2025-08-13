#include "diskjacker.hpp"
#include <iostream>
#include <thread>
#include <vector>
int main()
{
	if (memory::isHijacked())
	{
		std::cout << "CPUID Returned backdoor code" << std::endl;
		if (memory::init())
		{
			std::cout << "Memory initialized" << std::endl;
		}
	}
	else {
		std::cout << "CPUID didn't return backdoor code" << std::endl;
	}


	const UINT64 cr3 = memory::getCR3();
	std::cout << "CR3: " << cr3 << std::endl;

    UINT8 buffer[8] = {0};
    const UINT64 readPhysical = memory::readPhysical(0x100107000, (UINT64)buffer, sizeof(buffer));
    std::cout << "Read Physical: " << readPhysical << std::endl;

    std::cout << "Buffer bytes: ";
    for (size_t i = 0; i < sizeof(buffer); ++i) {
        std::cout << std::hex << std::uppercase << static_cast<int>(buffer[i]) << " ";
    }
    std::cout << std::dec << std::endl;

	std::cout << "PID: " << memory::getPIDByName(L"notepad.exe") << std::endl;
	memory::setTrackedProcessName(L"notepad.exe");

	Sleep(5000);

	UINT64 processPdb = memory::getTrackedPDB();

	std::cout << "Tracked Process PDB: " << std::hex << processPdb << std::dec << std::endl;

	GET_MODULE_INFO moduleInfo = memory::getModuleInfo(L"Notepad.exe");
	std::cout << "notepad.exe Base Address: " << std::hex << moduleInfo.ModuleBaseAddress << std::dec << std::endl;
	std::cout << "notepad.exe Size: " << moduleInfo.ModuleSize << std::endl;

	memset(buffer, 0, sizeof(buffer));
	UINT64 readVirtual = memory::readVirtual(moduleInfo.ModuleBaseAddress, (UINT64)buffer, sizeof(buffer));
	std::cout << "Read Virtual: " << readVirtual << std::endl;
	std::cout << "Buffer bytes after virtual read: ";
	for (size_t i = 0; i < sizeof(buffer); ++i) {
		std::cout << std::hex << std::uppercase << static_cast<int>(buffer[i]) << " ";
	}
	std::cout << std::dec << std::endl;

	system("pause");
}