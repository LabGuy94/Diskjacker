# Diskjacker
A proof of concept project which hijacks Hyper-Vs VM Exit at runtime using [DDMA](https://github.com/btbd/ddma).

## Video

https://github.com/user-attachments/assets/5e02db13-113d-44e1-90cb-c199b70d3d06

## How it works

Read at [readcc.net](https://readcc.net/posts/runtimehypervhijacking/), archived at [archive.org](https://web.archive.org/web/20250000000000*/https://readcc.net/posts/runtimehypervhijacking/).

## Requirements
1. AMD CPU with Virtualization Capabilities
2. Windows 11 24H2 (requires offset update in `GetVmcb` function in `hyperv.hpp` otherwise)
3. IOMMU Disabled
4. Hyper-V Enabled


## Usage
1. Compile the project using [Visual Studio 2022](https://visualstudio.microsoft.com/) and [WDK](https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk).
2. Use a tool like [HXD](https://mh-nexus.de/en/hxd/) or [bintoc](https://github.com/klyhthwy/bintoc/tree/master) to copy the bytes of `payload.sys` to `payloadData` inside of `payloadBytes.h`
3. Run loader passing kernel driver as parameter
4. Run usermode
5. Profit!
