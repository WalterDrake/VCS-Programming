#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <strsafe.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <string>
#include <process.h>
#include <conio.h>


#pragma comment(lib, "Ws2_32.lib")
#define DEFAULT_PORT "27015"
#define DEFAULT_BUFLEN 512

// Flag to indicate when to exit the threads when user exits the program
volatile bool exit_flag = false;

SOCKET ConnectSocket = INVALID_SOCKET;
TCHAR sendbuf[DEFAULT_BUFLEN];
int inputLen = 0;
HANDLE hMutex;
int iResult;


unsigned __stdcall RecvThread(void* data) {
	SOCKET ServerSocket = *(SOCKET*)data;
	char recvbuf[DEFAULT_BUFLEN];

	while (!exit_flag) {
		iResult = recv(ServerSocket, recvbuf, DEFAULT_BUFLEN - 1, 0);
		if (iResult > 0) {
			recvbuf[iResult] = '\0';

			WaitForSingleObject(hMutex, INFINITE);

			// clear current line on console
			printf("\r\x1b[K");

			_tprintf(TEXT("%hs\n"), recvbuf);
			_tprintf(TEXT("----------------------------------\n"));

			// redraw sendbuf
			_tprintf(TEXT("%.*s"), inputLen, sendbuf);
			fflush(stdout);

			ReleaseMutex(hMutex);
		}
		else if (iResult == 0) {
			_tprintf(TEXT("Connection closed\n"));
			break;
		}
		else {
			_tprintf(TEXT("recv failed: %d\n"), WSAGetLastError());
			break;
		}
	}
	return 0;
}

unsigned __stdcall SendThread(void* data) {
	SOCKET ConnectSocket = *(SOCKET*)data;
	while (!exit_flag) {
		int ch = _getch();

		WaitForSingleObject(hMutex, INFINITE);

		if (ch == '\r') { // ENTER
			if (_tcscmp(sendbuf, TEXT("/quit")) == 0) {
				exit_flag = true;
				iResult = shutdown(ConnectSocket, SD_BOTH);
				if (iResult == SOCKET_ERROR) {
					printf("shutdown failed: %d\n", WSAGetLastError());
					closesocket(ConnectSocket);
					WSACleanup();
					return 1;
				}
			}
			sendbuf[inputLen] = '\0';
			if (inputLen > 0) {
#ifdef UNICODE
				char sendbufA[DEFAULT_BUFLEN];
				size_t convertedChars = 0;
				wcstombs_s(&convertedChars, sendbufA, DEFAULT_BUFLEN, sendbuf, _TRUNCATE);
				const char* dataToSend = sendbufA;
#else
				const char* dataToSend = sendbuf;
#endif
				send(ConnectSocket, dataToSend, inputLen, 0);
				_tprintf(TEXT("\n-----------------------------------\n"));
			}
			// Reset input buffer
			inputLen = 0;
			sendbuf[0] = '\0';
		}
		else if (ch == '\b') { // BACKSPACE
			if (inputLen > 0) {
				inputLen--;
				sendbuf[inputLen] = '\0';
				printf("\r\x1b[K");
				_tprintf(TEXT("%.*s"), inputLen, sendbuf);
				fflush(stdout);
			}
		}
		else { // Normal character
			if (inputLen < DEFAULT_BUFLEN - 1) {
				sendbuf[inputLen++] = (char)ch;
				sendbuf[inputLen] = '\0';
				_tprintf(TEXT("%c"), ch);
				fflush(stdout);
			}
		}

		ReleaseMutex(hMutex);
	}
	return 0;
}


int _tmain(int argc, TCHAR* argv[])
{
	WSADATA wsaData;
	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		_tprintf(TEXT("WSAStartup failed: %d\n"), iResult);
		return 1;
	}
	_tprintf(TEXT("Winsock initialized successfully.\n"));

	struct addrinfoW* result = NULL,
		* ptr = NULL,
		hints;

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	// Resolve the server address and port
	iResult = GetAddrInfoW(argv[1], TEXT(DEFAULT_PORT), &hints, &result);
	if (iResult != 0) {
		_tprintf(TEXT("getaddrinfo failed: %d\n"), iResult);
		WSACleanup();
		return 1;
	}
	_tprintf(TEXT("Address resolved successfully.\n"));

	// Loop through all the results and connect to the first we can
	for (ptr = result; ptr != NULL; ptr = ptr->ai_next) {
		// Create a SOCKET for connecting to server
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET) {
			_tprintf(TEXT("Error at socket(): %ld\n"), WSAGetLastError());
			continue;
		}
		// Connect to server
		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR) {
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}

		_tprintf(TEXT("Socket created successfully.\n"));
		break;
	}

	FreeAddrInfoW(result);
	if (ConnectSocket == INVALID_SOCKET) {
		_tprintf(TEXT("Unable to connect to server!\n"));
		WSACleanup();
		return 1;
	}

	_tprintf(TEXT("Successfully connected to server.\n"));
	_tprintf(TEXT("=====================================\n"));


	// Create mutex
	hMutex = CreateMutex(NULL, FALSE, NULL);
	if (hMutex == NULL) {
		printf("CreateMutex failed: %lu\n", GetLastError());
		return 1;
	}
	HANDLE hRecv, hSend;
	unsigned threadRecv, threadSend;

	hRecv = (HANDLE)_beginthreadex(NULL, 0, RecvThread, &ConnectSocket, 0, &threadRecv);
	hSend = (HANDLE)_beginthreadex(NULL, 0, SendThread, &ConnectSocket, 0, &threadSend);

	if (hRecv == 0 || hSend == 0) {
		printf("Failed to create thread(s)\n");
		return 1;
	}

	WaitForSingleObject(hRecv, INFINITE);
	WaitForSingleObject(hSend, INFINITE);

	CloseHandle((HANDLE)hRecv);
	CloseHandle((HANDLE)hSend);

	if (hMutex) {
		CloseHandle(hMutex);
		hMutex = NULL;
	}

	// cleanup
	closesocket(ConnectSocket);
	WSACleanup();

	return 0;
}