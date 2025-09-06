#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <vector>
#include <unordered_map>
#include <string>

typedef struct {
	DWORD pid;
	std::basic_string<TCHAR> exeName;
	DWORD parentPid;
} ProcInfo;

int main(void)
{
	_tprintf(TEXT("\t\t\t\t\tTask Manager\n"));
	_tprintf(TEXT("==========================================================================================\n"));
	_tprintf(TEXT("%-10s %-45s %-15s %-40s\n"), TEXT("PID"), TEXT("Process Name"), TEXT("PPID"), TEXT("Parent Name"));

	// Create a snapshot of all processes in the system
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		_tprintf(TEXT("CreateToolhelp32Snapshot failed: %d"), GetLastError());
		return 1;
	}

	PROCESSENTRY32 pe;
	// Set the size of the structure before using it.
	pe.dwSize = sizeof(PROCESSENTRY32);

	std::vector<ProcInfo> processes;

	// Iterate through the processes in the snapshot
	if (Process32First(hProcessSnap, &pe)) {
		do {
			ProcInfo pi{};
			pi.pid = pe.th32ProcessID;
			pi.exeName = pe.szExeFile;
			pi.parentPid = pe.th32ParentProcessID;
			processes.push_back(pi);
		} while (Process32Next(hProcessSnap, &pe));
	}
	else {
		_tprintf(TEXT("Process32First failed: %d"), GetLastError());
		CloseHandle(hProcessSnap);
		return 1;
	}
	CloseHandle(hProcessSnap);

	// Build lookup table for pid to process name
	std::unordered_map<DWORD, std::basic_string<TCHAR>> pidToName;
	for (const auto& process : processes) {
		pidToName[process.pid] = process.exeName;
	}

	for (const auto& process : processes) {
		std::basic_string<TCHAR> parentName;
		auto it = pidToName.find(process.parentPid);
		if (it != pidToName.end()) {
			parentName = it->second;
		}
		_tprintf(TEXT("%-10u %-45s %-15u %-40s\n"), process.pid, process.exeName.c_str(), process.parentPid, parentName.c_str());
	}
	return 0;
}

