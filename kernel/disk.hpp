// Credits BTBD and Cutecatsandvirtualmachines (BTBD for original POC and ccvm for SCSI support). Removed ATA support because I felt like it.
// https://github.com/cutecatsandvirtualmachines/DDMA
// https://github.com/btbd/ddma

#include "defines.h"
#include <ntimage.h>
#include <scsi.h>
#include <cstddef>
NTSTATUS GetDeviceObjectList(IN PDRIVER_OBJECT driverObject, OUT PDEVICE_OBJECT** outDevices,
    OUT PULONG outDeviceCount) {

    ULONG count = 0;
    NTSTATUS status = IoEnumerateDeviceObjectList(driverObject, NULL, 0, &count);

    if (status != STATUS_BUFFER_TOO_SMALL) {
        return status;
    }

    ULONG size = count * sizeof(PDEVICE_OBJECT);
    PDEVICE_OBJECT* devices = (PDEVICE_OBJECT*)ExAllocatePool(NonPagedPoolNx, size);
    if (devices) {
        *outDeviceCount = count;

        status = IoEnumerateDeviceObjectList(driverObject, devices, size, &count);
        if (NT_SUCCESS(status)) {
            *outDevices = devices;
        }
        else {
            ExFreePool(devices);
        }
    }
    else {
        status = STATUS_INSUFFICIENT_RESOURCES;
    }

    return status;
}

BOOLEAN SCSIBuild10CDB(PSCSI_PASS_THROUGH_DIRECT srb, ULONGLONG offset, ULONG length, BOOLEAN Write) {
    if (!srb || offset >= 0x20000000000 || length < 1)
        return FALSE;

    LPCH cdb = (LPCH)srb->Cdb;

    if (Write == FALSE) {
        cdb[0] = SCSIOP_READ;
        cdb[1] = 0;
    }
    else {
        cdb[0] = SCSIOP_WRITE;
        cdb[1] = 0;
    }
    DWORD32 LBA = (DWORD32)(offset / SCSI_SECTOR_SIZE);

    cdb[2] = ((LPCH)&LBA)[3];
    cdb[3] = ((LPCH)&LBA)[2];
    cdb[4] = ((LPCH)&LBA)[1];
    cdb[5] = ((LPCH)&LBA)[0];
    cdb[6] = 0x00;

    SHORT CDBTLen = (SHORT)(length / SCSI_SECTOR_SIZE);
    cdb[7] = ((LPCH)&CDBTLen)[1];
    cdb[8] = ((LPCH)&CDBTLen)[0];
    cdb[9] = 0x00;
    return TRUE;
}

NTSTATUS ScsiIssueCommand(IN PDEVICE_OBJECT device, IN UCHAR operationCode, IN PVOID buffer) {
    KEVENT event;
    KeInitializeEvent(&event, SynchronizationEvent, FALSE);

    SCSI_PASS_THROUGH_DIRECT Srb = { 0 };
    CDB Cdb = { 0 };

    Srb.Length = sizeof(Srb);
    Srb.CdbLength = 10;
    Srb.SenseInfoLength = 0;
    Srb.SenseInfoOffset = sizeof(Srb);
    Srb.DataTransferLength = PAGE_SIZE;
    Srb.TimeOutValue = 5;
    Srb.DataBuffer = buffer;

    SCSIBuild10CDB(&Srb, 0, Srb.DataTransferLength, operationCode == SCSIOP_WRITE);

    IO_STATUS_BLOCK ioStatusBlock;
 
    PIRP irp = IoBuildDeviceIoControlRequest(IOCTL_SCSI_PASS_THROUGH_DIRECT, device, &Srb,
        sizeof(Srb), 0, 0, FALSE,
        &event, &ioStatusBlock);

    if (!irp) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    NTSTATUS status = IoCallDriver(device, irp);

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = ioStatusBlock.Status;
    }

    return status;
}


NTSTATUS ScsiReadPage(IN PDEVICE_OBJECT device, OUT PVOID dest) {
    return ScsiIssueCommand(device, SCSIOP_READ, dest);
}

NTSTATUS ScsiWritePage(IN PDEVICE_OBJECT device, IN PVOID src) {
    return ScsiIssueCommand(device, SCSIOP_WRITE, src);
}

NTSTATUS DiskCopy(IN PDISK disk, IN PVOID dest, IN PVOID src) {
    NTSTATUS status = ScsiWritePage(disk->Device, src);
    if (NT_SUCCESS(status)) {
        // Write to dest by reading from disk
        status = ScsiReadPage(disk->Device, dest);

        // Restore original sectors
        ScsiWritePage(disk->Device, disk->Buffer);
    }

    return status;
}

NTSTATUS DiskCopyPages(IN PDISK disk, IN PVOID dest, IN PVOID src, IN UINT64 pageCount) {
    NTSTATUS status = STATUS_SUCCESS;
    for (UINT64 i = 0; i < pageCount; ++i) {
        PVOID srcPage = (PVOID)((PUCHAR)src + i * PAGE_SIZE);
        PVOID destPage = (PVOID)((PUCHAR)dest + i * PAGE_SIZE);

        status = ScsiWritePage(disk->Device, srcPage);
        if (!NT_SUCCESS(status)) {
            break;
        }

        status = ScsiReadPage(disk->Device, destPage);
        if (!NT_SUCCESS(status)) {
            break;
        }

        ScsiWritePage(disk->Device, disk->Buffer);
    }
    return status;
}
BOOLEAN IsMicrosoftVirtualDisk(PDEVICE_OBJECT device, PVOID buffer) {
    SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER sptdwb = { 0 };
    PSCSI_PASS_THROUGH_DIRECT sptd = &sptdwb.spt;

    sptd->Length = sizeof(SCSI_PASS_THROUGH_DIRECT);
    sptd->CdbLength = 6;
    sptd->SenseInfoLength = 32;
    sptd->DataIn = SCSI_IOCTL_DATA_IN;
    sptd->DataTransferLength = 96;
    sptd->TimeOutValue = 10;
    sptd->DataBuffer = buffer;
    sptd->SenseInfoOffset = offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, ucSenseBuf);
    sptd->Cdb[0] = SCSIOP_INQUIRY;
    sptd->Cdb[4] = 96;

    KEVENT event;
    IO_STATUS_BLOCK iosb;
    KeInitializeEvent(&event, NotificationEvent, FALSE);

    PIRP irp = IoBuildDeviceIoControlRequest(
        IOCTL_SCSI_PASS_THROUGH_DIRECT,
        device,
        &sptdwb,
        sizeof(sptdwb),
        &sptdwb,
        sizeof(sptdwb),
        FALSE,
        &event,
        &iosb
    );

    if (!irp) {
        return FALSE;
    }

    NTSTATUS status = IoCallDriver(device, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    }

    if (!NT_SUCCESS(status)) {
        return FALSE;
    }

    PINQUIRYDATA inquiryData = (PINQUIRYDATA)buffer;
    CHAR vendorId[9] = { 0 };
    CHAR productId[17] = { 0 };
    RtlCopyMemory(vendorId, inquiryData->VendorId, 8);
    RtlCopyMemory(productId, inquiryData->ProductId, 16);
    if (RtlCompareMemory(&inquiryData->VendorId[0], "Msft    ", 8) == 8) {
        if (RtlCompareMemory(&inquiryData->ProductId[0], "Virtual Disk    ", 16) == 16) {
            return TRUE;
        }
    }

    return FALSE;
}
NTSTATUS DiskFind(OUT PDISK* outDisk) {
    PDISK disk = (PDISK)ExAllocatePool(NonPagedPoolNx, sizeof(DISK));
    if (!disk) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    RtlZeroMemory(disk, sizeof(*disk));

    UNICODE_STRING diskStr = RTL_CONSTANT_STRING(L"\\Driver\\Disk");
    PDRIVER_OBJECT diskObject;

    NTSTATUS status = ObReferenceObjectByName(&diskStr, OBJ_CASE_INSENSITIVE, NULL, 0,
        *IoDriverObjectType, KernelMode, NULL, (PVOID*)&diskObject);

    if (NT_SUCCESS(status)) {
        PDEVICE_OBJECT* devices;
        ULONG deviceCount;

        status = GetDeviceObjectList(diskObject, &devices, &deviceCount);

        if (NT_SUCCESS(status)) {
            status = STATUS_NOT_FOUND;

            for (ULONG i = 0; i < deviceCount; ++i) {
                PDEVICE_OBJECT device = devices[i];


                if (status == STATUS_NOT_FOUND && IsMicrosoftVirtualDisk(device, disk->Buffer) && NT_SUCCESS(ScsiReadPage(device, disk->Buffer))) {
                    disk->Device = device;
                    status = STATUS_SUCCESS;
                    continue;
                }

                ObDereferenceObject(device);
            }

            ExFreePool(devices);
        }

        ObDereferenceObject(diskObject);
    }

    if (NT_SUCCESS(status)) {
        *outDisk = disk;
    }
    else {
        ExFreePool(disk);
    }

    return status;
}