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
#include <process.h>
#include <vector>
#include <mutex>

#pragma comment(lib, "Ws2_32.lib")
#define DEFAULT_PORT "27015"
#define DEFAULT_BUFLEN 512

typedef struct {
	SOCKET socket;
	TCHAR ipStr[INET_ADDRSTRLEN];
	int port;
} ClientInfo;

std::vector<ClientInfo> g_clients; // Global vector to hold client information
std::mutex g_clientsMutex; // Mutex to protect access to the client vector


ClientInfo MakeClientInfo(SOCKET ClientSocket) {
	ClientInfo info;
	info.socket = ClientSocket;
	sockaddr_in clientAddr;
	int addrLen = sizeof(clientAddr);

	// Get the client's address and port
	if (getpeername(ClientSocket, (sockaddr*)&clientAddr, &addrLen) == 0) {
		InetNtopW(AF_INET, &clientAddr.sin_addr, info.ipStr, _countof(info.ipStr));
		info.port = ntohs(clientAddr.sin_port);
	}
	else {
		_tcscpy_s(info.ipStr, _countof(info.ipStr), TEXT("Unknown"));
		info.port = -1;
	}

	return info;
}

// Function prototype for the client thread
unsigned __stdcall ClientThread(void* data) {

	SOCKET ClientSocket = *(SOCKET*)data;
	char recvbuf[DEFAULT_BUFLEN];
	int iResult, iSendResult = 0;
	int recvbuflen = DEFAULT_BUFLEN;
	char sendbuf[DEFAULT_BUFLEN];
	char ip[INET_ADDRSTRLEN];
	bool notify = true;

	// safely initialized for avoiding garbage value
	ClientInfo clientInfo{};
	{
		std::lock_guard<std::mutex> lock(g_clientsMutex);
		// Return the first itorator that matches the ClientSocket
		auto it = std::find_if(g_clients.begin(), g_clients.end(),
			[ClientSocket](const ClientInfo& ci) {
				return ci.socket == ClientSocket;
			});

		if (it != g_clients.end()) {
			clientInfo = *it;
		}
	}

	do {

#ifdef UNICODE
		size_t convertedChars = 0;
		wcstombs_s(&convertedChars, ip, INET_ADDRSTRLEN, clientInfo.ipStr, _TRUNCATE);

#else
		strcpy_s(ip, INET_ADDRSTRLEN, ClientSendMsg.ipStr);
#endif

		if (notify)
		{
			sprintf_s(sendbuf, DEFAULT_BUFLEN, "Client %s:%d has joined the chat.", ip, clientInfo.port);
			{
				std::lock_guard<std::mutex> lock(g_clientsMutex);
				for (const ClientInfo& clientInfo : g_clients) {
					if (clientInfo.socket != ClientSocket) {
						send(clientInfo.socket, sendbuf, (int)strlen(sendbuf), 0);
						if (iSendResult == SOCKET_ERROR) {
							_tprintf(TEXT("send failed: %d to %s:%d\n"), WSAGetLastError(), clientInfo.ipStr, clientInfo.port);
						}
					}
				}

			}
			// clear the sendbuf
			sendbuf[0] = '\0';
			notify = false;
		}
		iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
		if (iResult > 0) {

			_tprintf(TEXT("Bytes received: %d\n"), iResult);
			_tprintf(TEXT("[%s:%d]: %.*hs\n"), clientInfo.ipStr, clientInfo.port, iResult, recvbuf);
			_tprintf(TEXT("-------------------------------------\n"));

			sprintf_s(sendbuf, DEFAULT_BUFLEN, "[%s:%d]: %.*s", ip, clientInfo.port, iResult, recvbuf);

			// Broadcast the received message to all other clients
			std::lock_guard<std::mutex> lock(g_clientsMutex);
			for (const ClientInfo& clientInfo : g_clients) {
				if (clientInfo.socket != ClientSocket) {
					send(clientInfo.socket, sendbuf, (int)strlen(sendbuf), 0);
					if (iSendResult == SOCKET_ERROR) {
						_tprintf(TEXT("send failed: %d to %s:%d\n"), WSAGetLastError(), clientInfo.ipStr, clientInfo.port);
					}
				}
			}
		}
		else if (iResult == 0) {
			{
				std::lock_guard<std::mutex> lock(g_clientsMutex);

				// Erase the vector client
				g_clients.erase(
					// Mark client for removal
					std::remove_if(g_clients.begin(), g_clients.end(),
						[ClientSocket](const ClientInfo& ci) {
							return ci.socket == ClientSocket;
						}),
					g_clients.end()
				);
			}

			closesocket(ClientSocket);

			_tprintf(TEXT("Client %s:%d disconnected.\n"),
				clientInfo.ipStr,
				clientInfo.port);
			_tprintf(TEXT("Amount of client is active: %d\n"), (int)g_clients.size());
		}
		else {
			_tprintf(TEXT("recv failed: %d\n"), WSAGetLastError());
			closesocket(ClientSocket);
		}

	} while (iResult > 0);
	return 0;
}

int _tmain(void)
{
	WSADATA wsaData;
	int iResult;

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
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the local address and port to be used by the server
	iResult = GetAddrInfoW(NULL, TEXT(DEFAULT_PORT), &hints, &result);
	if (iResult != 0) {
		_tprintf(TEXT("getaddrinfo failed: %d\n"), iResult);
		WSACleanup();
		return 1;
	}

	SOCKET ListenSocket = INVALID_SOCKET;

	// Create a SOCKET for the server to listen for client connections
	ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
	if (ListenSocket == INVALID_SOCKET) {
		_tprintf(TEXT("Error at socket(): %ld\n"), WSAGetLastError());
		FreeAddrInfoW(result);
		WSACleanup();
		return 1;
	}

	// Setup the TCP listening socket
	iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		_tprintf(TEXT("bind failed with error : % d\n"), WSAGetLastError());
		FreeAddrInfoW(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	FreeAddrInfoW(result);


	// Listening on the socket
	if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
		_tprintf(TEXT("Listen failed with error: %ld\n"), WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	_tprintf(TEXT("Server initialization successful\n"));
	_tprintf(TEXT("=====================================\n"));
	SOCKET ClientSocket;

	while (true)
	{
		ClientSocket = accept(ListenSocket, NULL, NULL);
		if (ClientSocket == INVALID_SOCKET) {
			_tprintf(TEXT("accept failed: %d\n"), WSAGetLastError());
			continue;
		}
		ClientInfo clientInfo = MakeClientInfo(ClientSocket);
		// Scope block for mutex lock to protect the global client list
		{
			std::lock_guard<std::mutex> lock(g_clientsMutex);
			g_clients.push_back(clientInfo);
		}
		_tprintf(TEXT("Client connected from %s:%d\n"), clientInfo.ipStr, clientInfo.port);
		_tprintf(TEXT("Amount of client is active: %d\n"), (int)g_clients.size());
		_tprintf(TEXT("=====================================\n"));

		// Spawn a thread for the new client
		HANDLE hThread;
		unsigned threadClient;
		hThread = (HANDLE)_beginthreadex(NULL, 0, ClientThread, &ClientSocket, 0, &threadClient);
		if (threadClient == 0) {
			_tprintf(TEXT("Failed to create thread for client: %d\n"), GetLastError());
			continue;
		}
		if (hThread) {
			CloseHandle(hThread);
		}
		else {
			_tprintf(TEXT("_beginthreadex failed.\n"));
		}
	}

	// clean up
	closesocket(ClientSocket);
	WSACleanup();
	return 0;
}