#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#include <Shlwapi.h>

#pragma comment(lib, "Shlwapi.lib")

int DirCommand(LPTSTR szDir, BOOL recursion)
{
	WIN32_FIND_DATA ffd;
	DWORD dwError = 0;

	// Array to store subdirectories
	TCHAR** arraySubDirs = NULL;
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
		// Convert the last-write time to local time
		FILETIME ftLocal;
		SYSTEMTIME st;
		FileTimeToLocalFileTime(&ffd.ftLastWriteTime, &ftLocal);
		FileTimeToSystemTime(&ftLocal, &st);

		if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			_tprintf(TEXT("%02d/%02d/%04d  %02d:%02d    <DIR>          %s\n"),st.wMonth, st.wDay, st.wYear,st.wHour, st.wMinute,ffd.cFileName);
			if (recursion && _tcscmp(ffd.cFileName, TEXT(".")) != 0 && _tcscmp(ffd.cFileName, TEXT("..")) != 0) {
				size_t lengthOfSubPath = _tcslen(szDir) + _tcslen(ffd.cFileName) + 1; // add for null terminator
				TCHAR* subPath = (TCHAR*)malloc(lengthOfSubPath * sizeof(TCHAR));
				if (subPath) {
					StringCchCopy(subPath, lengthOfSubPath, szDir);
					StringCchCat(subPath, lengthOfSubPath, ffd.cFileName);

					TCHAR** subDirs = (TCHAR**)realloc(arraySubDirs, (subDirCount + 1) * sizeof(TCHAR*));
					if (subDirs) {
						arraySubDirs = subDirs;
						arraySubDirs[subDirCount] = subPath;
						subDirCount++;
					}
					else {
						free(subPath);
					}
				}
			}
		}
		else {
			LARGE_INTEGER filesize;
			filesize.HighPart = ffd.nFileSizeHigh;
			filesize.LowPart = ffd.nFileSizeLow;
			_tprintf(TEXT("%02d/%02d/%04d  %02d:%02d %17lld %s\n"), st.wMonth, st.wDay, st.wYear, st.wHour, st.wMinute, filesize.QuadPart, ffd.cFileName);
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
			TCHAR* searchPath = NULL;
			size_t lengthOfSearchPath = _tcslen(arraySubDirs[i]) + 3; // add for wildcard and null terminator
			_tprintf(TEXT("\nDirectory of: %s\n"), arraySubDirs[i]);
			searchPath = (TCHAR*)malloc((lengthOfSearchPath * sizeof(TCHAR)));
			if (!searchPath) {
				_tprintf(TEXT("Memory allocation failed.\n"));
				return 1;
			}
			StringCchCopy(searchPath, lengthOfSearchPath, arraySubDirs[i]);
			StringCchCat(searchPath, lengthOfSearchPath, TEXT("\\*"));
			DirCommand(searchPath, true);

			free(searchPath);
			free(arraySubDirs[i]);
		}
	}
	free(arraySubDirs);
	return 0;
}

int _tmain(int argc, TCHAR* argv[])
{
	DWORD lengthOfPath = 0;
	TCHAR* currentDirectoryPath = NULL;
	LPCTSTR inputPath = NULL;
	HRESULT hr = NULL;
	BOOL useLongPrefix = FALSE;

	if (argc > 3) {
		_tprintf(TEXT("Too much arguments. Usage: %s [/S] <directory>\n"), argv[0]);
		return 1;
	}

	if ((argc == 1)) {
		inputPath = TEXT(".");
	}
	else {
		inputPath = argv[argc - 1];
	}

	// Get length of the full path
	lengthOfPath = GetFullPathName(inputPath, 0, NULL, NULL); // return the terminated string
	if (lengthOfPath == 0) {
		_tprintf(TEXT("GetFullPathName failed: %lu\n"), GetLastError());
		return 1;
	}

	useLongPrefix = (lengthOfPath >= MAX_PATH);

	if (useLongPrefix) {
		// add length for wildcard and path prefix
		lengthOfPath += 6;
	}
	else {
		// add length for wildcard
		lengthOfPath += 2;
	}

	currentDirectoryPath = (TCHAR*)malloc(lengthOfPath * sizeof(TCHAR));
	if (!currentDirectoryPath) {
		_tprintf(TEXT("Memory allocation failed.\n"));
		return 1;
	}

	if (GetFullPathName(inputPath, lengthOfPath, currentDirectoryPath, NULL) == 0) {
		_tprintf(TEXT("GetFullPathName failed: %lu\n"), GetLastError());
		free(currentDirectoryPath);
		return 1;
	}

	if (PathFileExists(currentDirectoryPath)) {
		_tprintf(TEXT("Target directory is %s\n"), currentDirectoryPath);
	}
	else {
		_tprintf(TEXT("Path does NOT exist: %s\n"), currentDirectoryPath);
	}

	if (useLongPrefix) {
		memmove(currentDirectoryPath + 4, currentDirectoryPath, lengthOfPath * sizeof(TCHAR));
		memcpy(currentDirectoryPath, TEXT("\\\\?\\"), 4 * sizeof(TCHAR));
	}

	// Append the wildcard to the directory path
	hr = StringCchCat(currentDirectoryPath, lengthOfPath, TEXT("\\*"));
	if (FAILED(hr)) {
		_tprintf(TEXT("Appending failed!\n"));
	}

	if (argc == 3 && _tcscmp(argv[1], TEXT("/S")) == 0) {
		if (DirCommand(currentDirectoryPath, TRUE))
			return 1;
	}
	else
	{
		if (DirCommand(currentDirectoryPath, FALSE))
			return 1;
	}
	free(currentDirectoryPath);
	return 0;
}


