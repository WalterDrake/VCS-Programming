#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>


void printError(TCHAR const* msg)
{
	_tprintf(TEXT("%s: %d\n"), msg, GetLastError());
}

int DirCommand(LPTSTR szDir, bool recursion)
{
	WIN32_FIND_DATA ffd;
	DWORD dwError = 0;

	// Array to store subdirectories
	TCHAR* subDirs[MAX_PATH];
	int subDirCount = 0;

	HANDLE hFind = FindFirstFile(szDir, &ffd);
	if (hFind == INVALID_HANDLE_VALUE) {
		_tprintf(TEXT("FindFirstFile failed (%lu)\n"), GetLastError());
		return 1;
	}

	size_t len = _tcslen(szDir);
	if (len > 0 && szDir[len - 1] == TEXT('*'))
		szDir[len - 1] = TEXT('\0'); // Remove wildcard for path building

	do {
		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			_tprintf(TEXT("<DIR>  %s\n"), ffd.cFileName);

			if (recursion && _tcscmp(ffd.cFileName, TEXT(".")) != 0 && _tcscmp(ffd.cFileName, TEXT("..")) != 0) {
				subDirs[subDirCount] = (TCHAR*)malloc(MAX_PATH * sizeof(TCHAR));
				StringCchCopy(subDirs[subDirCount], MAX_PATH, szDir);
				StringCchCat(subDirs[subDirCount], MAX_PATH, ffd.cFileName);
				subDirCount++;
			}
		}
		else {
			_tprintf(TEXT("       %s\n"), ffd.cFileName);
		}
	} while (FindNextFile(hFind, &ffd) != 0);

	dwError = GetLastError();
	FindClose(hFind);

	if (dwError != ERROR_NO_MORE_FILES) {
		_tprintf(TEXT("FindNextFile failed (%lu)\n"), dwError);
		return 1;
	}

	// recurse into subfolders
	if (recursion) {
		for (int i = 0; i < subDirCount; i++) {
			TCHAR searchPath[MAX_PATH];
			_tprintf(TEXT("\nDirectory of: %s\n"), subDirs[i]);
			StringCchCopy(searchPath, MAX_PATH, subDirs[i]);
			StringCchCat(searchPath, MAX_PATH, TEXT("\\*"));
			DirCommand(searchPath, true);
			free(subDirs[i]); // Free allocated memory for subdirectory
		}
	}
	return 0;
}

int _tmain(int argc, TCHAR* argv[])
{

	size_t length_of_arg;
	TCHAR szDir[MAX_PATH];
	TCHAR* szSubDir[MAX_PATH];

	if (argc < 2) {
		_tprintf(TEXT("Usage: %s [/S] <directory>\n"), argv[0]);
		return 1;
	}

	if (argc > 3) {
		_tprintf(TEXT("Too much arguments. Usage: %s [/S] <directory>\n"), argv[0]);
		return 1;
	}

	// Determine the length of the directory path argument not exceeding MAX_PATH
	if (FAILED(StringCchLengthW(argv[argc - 1], MAX_PATH, &length_of_arg)))
	{
		printError(TEXT("StringCchLength failed with error"));
		return 1;
	}

	if (length_of_arg > MAX_PATH - 3)
	{
		printError(TEXT("Directory path is too long.\n"));
		return 1;
	}
	_tprintf(TEXT("Target directory is %s\n"), argv[argc - 1]);

	StringCchCopy(szDir, MAX_PATH, argv[argc - 1]);
	// Append the wildcard to the directory path
	StringCchCat(szDir, MAX_PATH, TEXT("\\*"));

	if (argc == 3 && _tcscmp(argv[1], TEXT("/S")) == 0) {
		if (DirCommand(szDir, true))
			return 1;
	}
	else
	{
		if (DirCommand(szDir, false))
			return 1;
	}
	return 0;
}


