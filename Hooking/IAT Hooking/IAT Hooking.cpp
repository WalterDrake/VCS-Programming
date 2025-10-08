#include <Windows.h>
#include <tchar.h>

//===============================================================================================//
// The original code by https://www.ired.team/offensive-security/code-injection-process-injection/import-adress-table-iat-hooking

// define MessageBoxA prototype
// create a function pointer type for saving the original MessageBoxA address
using PrototypeMessageBox = int (WINAPI*)(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);

// remember memory address of the original Windows API
PrototypeMessageBox originalMsgBox = MessageBoxW;

int hookedMessageBox(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	MessageBoxA(NULL, "Successful Hooking", "IAT Hooking", 0);
	// execute the original NessageBoxA
	return originalMsgBox(hWnd, lpText, lpCaption, uType);
}

int _tmain(void)
{
	MessageBoxW(NULL, L"Hello Before Hooking", L"IAT Hooking", 0);

	LPVOID imageBase = GetModuleHandleW(NULL);
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)imageBase;
	PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((DWORD_PTR)imageBase + pDosHeader->e_lfanew);

	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
	// RVA of the import directory table
	IMAGE_DATA_DIRECTORY importsDirectory = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	// First entry in the import directory table
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)imageBase);

	char* libraryNameANSI = NULL;
	HMODULE library = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL;

	while (pImportDescriptor->Name != NULL)
	{
		libraryNameANSI = (char*)((DWORD_PTR)imageBase + pImportDescriptor->Name);

		wchar_t libraryNameW[MAX_PATH];
		MultiByteToWideChar(CP_ACP, 0, libraryNameANSI, -1, libraryNameW, MAX_PATH);

		library = LoadLibraryW(libraryNameW);
		if (library)
		{
			PIMAGE_THUNK_DATA pOriginalFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + pImportDescriptor->OriginalFirstThunk);
			PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((DWORD_PTR)imageBase + pImportDescriptor->FirstThunk);
			// iterate through all functions in this DLL
			while (pOriginalFirstThunk->u1.AddressOfData != NULL)
			{
				functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)imageBase + pOriginalFirstThunk->u1.AddressOfData);

				wchar_t functionNameW[MAX_PATH];
				MultiByteToWideChar(CP_ACP, 0, (char*)functionName->Name, -1, functionNameW, MAX_PATH);

				if (wcscmp(functionNameW, L"MessageBoxW") == 0)
				{
					DWORD dwOldProtect1 = 0;
					DWORD dwOldProtect2 = 0;
					VirtualProtect((LPVOID)(&pFirstThunk->u1.Function), sizeof(ULONG_PTR), PAGE_READWRITE, &dwOldProtect1);

					// swap MessageBoxW address with address of hookedMessageBox
					pFirstThunk->u1.Function = (ULONG_PTR)hookedMessageBox;

					// revert to the previous memory protection flags...
					VirtualProtect((LPVOID)(&pFirstThunk->u1.Function), sizeof(ULONG_PTR), dwOldProtect1, &dwOldProtect2);
				}
				pOriginalFirstThunk++;
				pFirstThunk++;
			}
		}
		pImportDescriptor++;
	}

	// When program execution call MessageBoxW, the address in IAT will point to hookedMessageBox,
	// call MessageBoxA inside hookedMessageBox and then call the original MessageBoxW
	MessageBoxW(NULL, L"Hello After Hooking", L"IAT Hooking", 0);

	return 0;
}