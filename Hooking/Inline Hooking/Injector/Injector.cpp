#include <Windows.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>

int _tmain(int argc, TCHAR* argv[])
{
	TCHAR dllPath[MAX_PATH];
	TOKEN_PRIVILEGES priv = { 0 };
	HANDLE hToken = NULL;
	PROCESSENTRY32 pe = {};
	pe.dwSize = sizeof(PROCESSENTRY32);
	USHORT procMachine = 0, nativeMachine = 0;
	DWORD dwProcessId = 0;

	DWORD len = GetFullPathNameW(L"Hook.dll", MAX_PATH, dllPath, NULL);
	if (len == 0) {
		_tprintf(_T("Can't find Hook.dll\n"));
		return 1;
	}
	if (len > MAX_PATH) {
		_tprintf(_T("Path to Hook.dll is too long\n"));
		return 1;
	}

	// Privilege escalation process
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

	dwProcessId = (DWORD)_tcstoul(argv[1], NULL, 10);

	HANDLE hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, dwProcessId);
	if (!hProc)
	{
		_tprintf(TEXT("OpenProcess(%d) failed: %d\n"), dwProcessId, GetLastError());
		return 1;
	}

	// Check if target process is 32-bit
	IsWow64Process2(hProc, &procMachine, &nativeMachine);
	if (procMachine == IMAGE_FILE_MACHINE_I386)
	{
		_tprintf(TEXT("Target process is 32-bit.\n"));
		CloseHandle(hProc);
		return 1;
	}

	SIZE_T lengthPath = (wcslen(dllPath) + 1) * sizeof(wchar_t);
	LPVOID remoteBuffer = VirtualAllocEx(hProc, nullptr, lengthPath, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!remoteBuffer)
	{
		_tprintf(TEXT("VirtualAllocEx failed: %d\n"), GetLastError());
		CloseHandle(hProc);
		return FALSE;
	}
	if (!WriteProcessMemory(hProc, remoteBuffer, (LPVOID)dllPath, lengthPath, nullptr))
	{
		_tprintf(TEXT("WriteProcessMemory failed: %d\n"), GetLastError());
		VirtualFreeEx(hProc, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return FALSE;
	}

	LPTHREAD_START_ROUTINE threatStartRoutineAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleW(TEXT("Kernel32.dll")), "LoadLibraryW");
	HANDLE hThread = CreateRemoteThread(hProc, NULL, 0, threatStartRoutineAddress, remoteBuffer, 0, NULL);
	if (!hThread) {
		std::wcerr << L"CreateRemoteThread failed: " << GetLastError() << L"\n";
		VirtualFreeEx(hProc, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return FALSE;
	}

	DWORD wait = WaitForSingleObject(hThread, INFINITE);
	if (wait == WAIT_FAILED) {
		std::wcerr << L"WaitForSingleObject failed: " << GetLastError() << L"\n";
		CloseHandle(hThread);
		VirtualFreeEx(hProc, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return FALSE;
	}

	DWORD exitCode = 0;
	if (!GetExitCodeThread(hThread, &exitCode)) {
		std::wcerr << L"GetExitCodeThread failed: " << GetLastError() << L"\n";
		CloseHandle(hThread);
		VirtualFreeEx(hProc, remoteBuffer, 0, MEM_RELEASE);
		CloseHandle(hProc);
		return FALSE;
	}

	if (exitCode == 0) {
		std::wcerr << L"Remote LoadLibraryW returned NULL (failed to load). GetLastError inside target unknown.\n";
	}
	else {
		std::wcout << L"Remote LoadLibraryW succeeded, module handle: 0x" << std::hex << exitCode << std::dec << L"\n";
	}

	CloseHandle(hThread);
	VirtualFreeEx(hProc, remoteBuffer, 0, MEM_RELEASE);
	CloseHandle(hProc);
	return 0;
}