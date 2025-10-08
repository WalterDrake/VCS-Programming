#include <tchar.h>
#include <windows.h>
#include <array>
#include <psapi.h>

// This code is based on the tutorial by CodeReversing, see: https://www.codereversing.com/archives/598

// function prototype saving address of MessageBoxW
using PrototypeMessageBox = int (WINAPI*)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);
static PrototypeMessageBox originalMsgBox;

int hookedMessageBox(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	MessageBoxA(NULL, "Successful Hooking", "EAT Hooking", 0);
	// execute the original NessageBoxA
	return originalMsgBox(hWnd, lpText, lpCaption, uType);
}

// Create the byte array for the jump instruction to hook function
// For more details, see: https://www.codereversing.com/archives/592
// The reason, we need to create CreateJumpBytes function is RVA of EAT has a DWORD type.
// If hook function is out of the 4GB range from the module load address, DWORD cannot hold the address of the hook function.
// For safety, we create a function near the module and jump to the hook function from there.
std::array<unsigned char, 12> CreateJumpBytes(const void* const destinationAddress) {

	std::array<unsigned char, 12> jumpBytes{ {
			/*mov rax, 0xCCCCCCCCCCCCCCCC*/
			0x48, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,

			/*jmp rax*/
			0xFF, 0xE0
		} };

	// Replace placeholder value with the actual hook address
	const auto address{ reinterpret_cast<size_t>(destinationAddress) };
	std::memcpy(&jumpBytes[2], &address, sizeof(void*));

	return jumpBytes;
}

int _tmain(void*)
{
	// The original address of MessageBoxW
	PrototypeMessageBox UnusedMessageBoxAOriginalFncPtr = reinterpret_cast<PrototypeMessageBox>(GetProcAddress(GetModuleHandleW(L"user32.dll"), "MessageBoxW"));

	// Get base address of user32.dll
	HMODULE moduleBaseAddress = GetModuleHandleW(L"user32.dll");
	if (!moduleBaseAddress)
	{
		moduleBaseAddress = LoadLibraryW(L"user32.dll");

		if (moduleBaseAddress == nullptr)
		{
			_tprintf(_T("Failed to load user32.dll\n"));
			return 1;
		}
	}

	MessageBoxW(NULL, L"Hello Before Hooking", L"EAT Hooking", 0);

	// get the DOS header
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)moduleBaseAddress;

	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		_tprintf(_T("Not a valid PE file\n"));
		return 1;
	}

	// get the NT header
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)moduleBaseAddress + pDosHeader->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	// the address of the modules export directory
	IMAGE_DATA_DIRECTORY exportDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	// get the VA of the export directory
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)(exportDirectory.VirtualAddress + (DWORD_PTR)moduleBaseAddress);

	// get the arrays of the export directory
	DWORD* pAddressArray = (DWORD*)((DWORD_PTR)moduleBaseAddress + pExportDirectory->AddressOfFunctions);
	DWORD* pNameArray = (DWORD*)((DWORD_PTR)moduleBaseAddress + pExportDirectory->AddressOfNames);
	WORD* pOrdinalArray = (WORD*)((DWORD_PTR)moduleBaseAddress + pExportDirectory->AddressOfNameOrdinals);

	DWORD* pFunctionAddress = nullptr;

	// Loop through the names of the exported functions
	for (size_t index{}; index < pExportDirectory->NumberOfNames; index++) {
		TCHAR* exportFunctionName = (TCHAR*)((DWORD_PTR)moduleBaseAddress + pNameArray[index]);

		wchar_t functionNameW[MAX_PATH];
		MultiByteToWideChar(CP_ACP, 0, (char*)exportFunctionName, -1, functionNameW, MAX_PATH);

		if (wcscmp(functionNameW, L"MessageBoxW") == 0)
		{
			// get address of MessageBoxW in EAT
			pFunctionAddress = &pAddressArray[pOrdinalArray[index]];
		}
	}
	if (!pFunctionAddress)
	{
		_tprintf(_T("Function not found in export table\n"));
		return 1;
	}

	// If we debug this, we can see that originalMsgBox has same address as UnusedMessageBoxAOriginalFncPtr
	originalMsgBox = reinterpret_cast<PrototypeMessageBox>((DWORD_PTR)moduleBaseAddress + *pFunctionAddress);

	const auto jumpBytes = CreateJumpBytes(hookedMessageBox);

	MODULEINFO moduleInfo{};
	// retrive information about the module
	GetModuleInformation(GetCurrentProcess(), moduleBaseAddress, &moduleInfo, sizeof(MODULEINFO));

	// get address after the module
	auto allocAddress = reinterpret_cast<DWORD_PTR>(moduleInfo.lpBaseOfDll) + moduleInfo.SizeOfImage;

	void* allocatedAddress{};
	constexpr size_t ALLOC_ALIGNMENT = 0x10000;
	do {
		allocatedAddress = VirtualAlloc(reinterpret_cast<void*>(allocAddress), jumpBytes.size(), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		allocAddress += ALLOC_ALIGNMENT;
	} while (allocatedAddress == nullptr);


	memcpy(allocatedAddress, jumpBytes.data(), jumpBytes.size());

	DWORD oldProtections{};
	VirtualProtect(pFunctionAddress, sizeof(void*), PAGE_EXECUTE_READWRITE, &oldProtections);
	// Overwrite the RVA of MessageBoxW in EAT with the RVA of our allocated memory containing the jump instruction
	*pFunctionAddress = static_cast<DWORD>(reinterpret_cast<DWORD_PTR>(allocatedAddress) - reinterpret_cast<DWORD_PTR>(moduleBaseAddress));
	VirtualProtect(pFunctionAddress, sizeof(void*), oldProtections, &oldProtections);

	PrototypeMessageBox MessageBoxAFnc = reinterpret_cast<PrototypeMessageBox>(GetProcAddress(GetModuleHandleA("user32.dll"), "MessageBoxW"));

	MessageBoxAFnc(NULL, L"Hello After Hooking", L"EAT Hooking", 0);
	return 0;

}