#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <tlhelp32.h>

typedef struct {
	DWORD pid;
	TCHAR exeName[MAX_PATH];
	DWORD parentPid;
} ProcInfo;

void printError(TCHAR const* msg)
{
	_tprintf(TEXT("%s: %d\n"), msg, GetLastError());
}

int taskManager()
{
	// Create a snapshot of all processes in the system
	HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		printError(TEXT("CreateToolhelp32Snapshot failed"));
		return 1;
	}

	PROCESSENTRY32 pe;
	// Set the size of the structure before using it.
	pe.dwSize = sizeof(PROCESSENTRY32);

	ProcInfo processes[1024];
	unsigned int count = 0;
	// Iterate through the processes in the snapshot
	if (Process32First(hProcessSnap, &pe))
	{
		do {
			processes[count].pid = pe.th32ProcessID;
			_tcsncpy_s(processes[count].exeName, pe.szExeFile, sizeof(pe.szExeFile));
			processes[count].parentPid = pe.th32ParentProcessID;
			count++;
		} while (Process32Next(hProcessSnap, &pe));
	}
	else
	{
		printError(TEXT("Process32First failed"));
		CloseHandle(hProcessSnap);
		return 1;
	}
	CloseHandle(hProcessSnap);
	for (unsigned int i = 0; i < count; i++)
	{
		TCHAR szParentProcessName[MAX_PATH] = TEXT("");
		for (unsigned int j = 0; j < count; j++)
		{
			if (processes[j].pid == processes[i].parentPid)
			{
				_tcsncpy_s(szParentProcessName, processes[j].exeName, sizeof(pe.szExeFile));
				break;
			}
		}
		_tprintf(TEXT("%-10u %-45s %-15u %-40s\n"), processes[i].pid, processes[i].exeName, processes[i].parentPid, szParentProcessName);
	}
	return 0;
}


int main(void)
{
	_tprintf(TEXT("\t\t\t\t\tTask Manager\n"));
	_tprintf(TEXT("==========================================================================================\n"));
	_tprintf(TEXT("%-10s %-45s %-15s %-40s\n"), TEXT("PID"), TEXT("Process Name"), TEXT("PPID"), TEXT("Parent Name"));
	if (taskManager())
		return 1;
	return 0;
}

