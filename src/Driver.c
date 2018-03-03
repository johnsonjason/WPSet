
#include <ntifs.h>
#include <ntdef.h>
#include <wdf.h>
#include <intrin.h>
#define WP_OFF 0
#define WP_ON 1
#define BASE_SIGNATURE 0
#define NT_SIGNATURE 1
#define K32_ADDRESS NULL
#define K32_SHELL_BUFFER NULL
#define K32_SIZE 0

typedef unsigned long long QWORD;

DRIVER_INITIALIZE DriverEntry;
PDEVICE_OBJECT pDeviceObject;
UNICODE_STRING dev;
HANDLE g_ProcessId;
DWORD_PTR SignatureAddress;
PVOID ModuleBase;

void SetWriteProtection(BOOLEAN Protection)
{
	QWORD cr0 = __readcr0();
	switch (Protection)
	{
	case WP_OFF:
		if ((BOOLEAN)((cr0 >> 16) & 0x1) == WP_ON)
		{
			cr0 ^= 1ULL << 16;
			__writecr0(cr0);
		}
		break;
	case WP_ON:
		if ((BOOLEAN)((cr0 >> 16) & 0x1) == WP_OFF)
		{
			cr0 ^= 1ULL << 16;
			__writecr0(cr0);
		}
		return;
	}
}

BOOLEAN CheckSignature64(DWORD_PTR SignaturePtr, DWORD64 Signature)
{
	__try
	{
		ProbeForRead((PVOID)SignaturePtr, sizeof(DWORD64), TYPE_ALIGNMENT(char));
		if (RtlCompareMemory((PVOID)SignaturePtr, &Signature, sizeof(DWORD64)) == sizeof(DWORD64))
			return TRUE;
		else
			return FALSE;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		DbgPrint("Signature access failed - exception");
		return FALSE;
	}
}

VOID ProcessLoadImageCallback(_In_opt_ PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo)
{
	if (!ProcessId)
	{
		if (CheckSignature64(SignatureAddress, BASE_SIGNATURE))
			ProcessId = ProcessId;
	}
	else
	{
		if (CheckSignature64(SignatureAddress, NT_SIGNATURE))
			ModuleBase = ImageInfo->ImageBase;
	}
}


VOID SetShellCode(PVOID Address, PVOID Buffer, ULONG BufferSize)
{
	PMDL ShellMemory = IoAllocateMdl(Address, BufferSize, FALSE, FALSE, NULL);
	__try 
	{
		MmProbeAndLockPages(ShellMemory, UserMode, IoReadAccess);
		MmProtectMdlSystemAddress(ShellMemory, PAGE_EXECUTE_READWRITE);
		RtlCopyMemory(Address, Buffer, BufferSize);
		MmUnlockPages(ShellMemory);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		if (ShellMemory != NULL)
			IoFreeMdl(ShellMemory);
		DbgPrint("Exception occurred with MDL");
		return;
	}
	if (ShellMemory != NULL)
		IoFreeMdl(ShellMemory);
}


VOID TWorker(PVOID Context)
{
	KeSetSystemAffinityThread((KAFFINITY)0x00000001);
	KAPC_STATE attach_apc;
	PEPROCESS process;
	LARGE_INTEGER sTime;
	sTime.QuadPart = 10000;

	PsSetLoadImageNotifyRoutine(ProcessLoadImageCallback);

	while (!ModuleBase)
		KeDelayExecutionThread(KernelMode, FALSE, &sTime);

	PsRemoveLoadImageNotifyRoutine(ProcessLoadImageCallback);

	SetWriteProtection(WP_ON);

	PsLookupProcessByProcessId(g_ProcessId, &process);
	KeStackAttachProcess(process, &attach_apc);
	SetShellCode(K32_ADDRESS, K32_SHELL_BUFFER, K32_SIZE);
	KeUnstackDetachProcess(&attach_apc);

	PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	IoDeleteDevice(pDriverObject->DeviceObject);
	return 0;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT  DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
	NTSTATUS status;
	WDF_DRIVER_CONFIG config;
	IoCreateDevice(DriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);

	HANDLE hControl;
	status = PsCreateSystemThread(&hControl, (ACCESS_MASK)0, NULL, NULL, NULL, TWorker, NULL);

	if (!NT_SUCCESS(status))
		return status;

	ZwClose(hControl);
	DriverObject->DriverUnload = UnloadDriver;
	return STATUS_SUCCESS;
}
