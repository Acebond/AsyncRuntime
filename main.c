#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <MSWSock.h>
#include <Windows.h>
#include <winternl.h>

#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ntdll.lib")

#define ArraySize(x) (sizeof x / sizeof x[0])

#define LISTEN_PORT     10080
#define BUF_SIZE        4096
#define BATCH_SIZE      64
#define WORKER_THREADS  4

#define ADDR_SIZE (sizeof(SOCKADDR_IN) + 16)

#define FIBER_STACK_SIZE (256 * 1024) // 256 KB

#define LOG_ERROR_CODE(func, code) printf("[" __FUNCTION__ "] " func " failed with error: %lu\n", code)
#define LOG_ERROR(func) LOG_ERROR_CODE(func, GetLastError())

typedef enum {
	KEY_IO,
	KEY_START,
	KEY_CLEANUP,
	KEY_SHUTDOWN,
} OpKey;

typedef struct {
	OVERLAPPED ov;
	LPVOID     fiber;
	DWORD      bytes;
	DWORD      error;
} AsyncOp;

typedef struct {
	SOCKET   clientSock;
	WCHAR    remoteHost[64];
	CHAR     recvBuf[BUF_SIZE];
	CHAR     sendBuf[BUF_SIZE];
	DWORD    recvBytes;
} ClientContext;

LPFN_ACCEPTEX             fnAcceptEx             = NULL;
LPFN_GETACCEPTEXSOCKADDRS fnGetAcceptExSockaddrs = NULL;
LPFN_CONNECTEX            fnConnectEx            = NULL;

// Needed for custom scheduler of userlands threads
static __declspec(thread) LPVOID tls_schedulerFiber = NULL;

// Needed for SetConsoleCtrlHandler and to process the OS signals
static HANDLE g_hIOCP = NULL;

// awaitOp — the "await" primitive
// Stores the current fiber in the op, suspends back to the scheduler.
// Execution resumes here once IOCP signals completion.
inline void awaitOp(AsyncOp* op) {
	op->fiber = GetCurrentFiber();
	SwitchToFiber(tls_schedulerFiber);
	// << resumes here after IOCP fires >>
}

int AsyncRecv(SOCKET socket, CHAR* buf, ULONG len, DWORD* bytesRecv) {

	AsyncOp op = { 0 };

	WSABUF wsaBuf = {
		.len = len, 
		.buf = buf 
	};

	DWORD flags = 0;

	if (WSARecv(socket, &wsaBuf, 1, NULL, &flags, &op.ov, NULL) == SOCKET_ERROR && 
		WSAGetLastError() != WSA_IO_PENDING) 
	{
		LOG_ERROR("WSARecv");
		return SOCKET_ERROR;
	}

	awaitOp(&op);

	*bytesRecv = op.bytes;
	return (op.error == ERROR_SUCCESS) ? 0 : SOCKET_ERROR;
}

int AsyncSend(SOCKET socket, CHAR* buf, ULONG len) {

	AsyncOp op = { 0 };

	WSABUF wsaBuf = { 
		.len = len, 
		.buf = buf 
	};

	if (WSASend(socket, &wsaBuf, 1, NULL, 0, &op.ov, NULL) == SOCKET_ERROR && 
		WSAGetLastError() != WSA_IO_PENDING) 
	{
		LOG_ERROR("WSASend");
		return SOCKET_ERROR;
	}

	awaitOp(&op);

	return (op.error == ERROR_SUCCESS) ? 0 : SOCKET_ERROR;
}

SOCKET AsyncAccept(SOCKET listenSocket, SOCKADDR* addr, int* addrlen) {

	// AcceptEx writes local+remote address into this buffer.
	// The (+16) is a quirk of AcceptEx — it needs 16 bytes of padding per addr.
	char addrBuf[2 * ADDR_SIZE] = { 0 };

	// Pre-create the client socket
	SOCKET clientSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (clientSocket == INVALID_SOCKET) {
		LOG_ERROR("WSASocket");
		return INVALID_SOCKET;
	}

	AsyncOp op = { 0 };

	DWORD bytesReceived = 0;
	BOOL ok = fnAcceptEx(
		listenSocket, 
		clientSocket, 
		addrBuf, 
		0, 
		ADDR_SIZE, 
		ADDR_SIZE, 
		&bytesReceived, 
		&op.ov);

	if (!ok && WSAGetLastError() != ERROR_IO_PENDING) {
		LOG_ERROR("AcceptEx");
		closesocket(clientSocket);
		return INVALID_SOCKET;
	}

	// suspend until a client connects
	awaitOp(&op);

	if (op.error != ERROR_SUCCESS) {
		LOG_ERROR_CODE("AcceptEx", op.error);
		closesocket(clientSocket);
		return INVALID_SOCKET;
	}

	// AcceptEx requires this setsockopt so that getpeername() etc. work
	setsockopt(clientSocket, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
		(char*)&listenSocket, sizeof(listenSocket));

	if (addr && addrlen) 
	{
		SOCKADDR* localAddr  = NULL;
		SOCKADDR* remoteAddr = NULL;
		int localAddrLen  = 0;
		int remoteAddrLen = 0;

		fnGetAcceptExSockaddrs(
			addrBuf, 0,
			sizeof(SOCKADDR_IN) + 16,
			sizeof(SOCKADDR_IN) + 16,
			&localAddr, &localAddrLen,
			&remoteAddr, &remoteAddrLen);

		if (*addrlen < remoteAddrLen) {
			LOG_ERROR_CODE("GetAcceptExSockaddrs", WSAEFAULT);
			closesocket(clientSocket);
			return INVALID_SOCKET;
		}

		memcpy(addr, remoteAddr, remoteAddrLen);
		*addrlen = remoteAddrLen;
	}

	return clientSocket;
}

SOCKET AsyncConnect(SOCKADDR* remoteAddr, int remoteAddrLen) {

	// ConnectEx requires an overlapped socket
	SOCKET sock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (sock == INVALID_SOCKET) {
		LOG_ERROR("WSASocket");
		return INVALID_SOCKET;
	}

	// ConnectEx requires the socket to already be bound
	// sin_port = 0 so the OS picks an ephemeral port
	SOCKADDR_IN localAddr     = { 0 };
	localAddr.sin_family      = AF_INET;
	localAddr.sin_port        = 0;
	localAddr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sock, (SOCKADDR*)&localAddr, sizeof(localAddr)) == SOCKET_ERROR) {
		LOG_ERROR("bind");
		closesocket(sock);
		return INVALID_SOCKET;
	}

	// Associate with the IOCP so completions are delivered to the scheduler
	if (CreateIoCompletionPort((HANDLE)sock, g_hIOCP, KEY_IO, 0) == NULL) {
		LOG_ERROR("CreateIoCompletionPort");
		closesocket(sock);
		return INVALID_SOCKET;
	}

	AsyncOp op = { 0 };

	DWORD bytesSent = 0;
	BOOL ok = fnConnectEx(
		sock,
		remoteAddr,
		remoteAddrLen,
		NULL, 0,
		&bytesSent,
		&op.ov);

	if (!ok && WSAGetLastError() != ERROR_IO_PENDING) {
		LOG_ERROR("ConnectEx");
		closesocket(sock);
		return INVALID_SOCKET;
	}

	// Suspend until the connection completes (or fails)
	awaitOp(&op);

	if (op.error != ERROR_SUCCESS) {
		LOG_ERROR_CODE("ConnectEx", op.error);
		closesocket(sock);
		return INVALID_SOCKET;
	}

	// Required after ConnectEx so that shutdown(), getpeername(), etc. work
	setsockopt(sock, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0);

	return sock;
}

void WINAPI HandleClient(LPVOID param) {

	ClientContext* clientContext = (ClientContext*)param;
	SOCKET         clientSocket  = clientContext->clientSock;

	printf("[%ls] Connected\n", clientContext->remoteHost);

	while (1) {
		DWORD bytesRecv = 0;
		int rc = AsyncRecv(clientSocket, clientContext->recvBuf, BUF_SIZE - 1, &bytesRecv);

		if (rc == SOCKET_ERROR || bytesRecv == 0) {
			// 0 bytes = graceful close; SOCKET_ERROR = reset
			break;
		}

		printf("[%ls] Received %lu bytes\n", clientContext->remoteHost, bytesRecv);

		// Echo back
		memcpy(clientContext->sendBuf, clientContext->recvBuf, bytesRecv);

		rc = AsyncSend(clientSocket, clientContext->sendBuf, (int)bytesRecv);
		if (rc == SOCKET_ERROR) {
			break;
		}

		printf("[%ls] Sent %lu bytes\n", clientContext->remoteHost, bytesRecv);
	}

	printf("[%ls] Disconnected\n", clientContext->remoteHost);
	closesocket(clientSocket);
	HeapFree(GetProcessHeap(), 0, clientContext);
	
	// Signal the scheduler that this fiber is done
	PostQueuedCompletionStatus(g_hIOCP, 0, KEY_CLEANUP, GetCurrentFiber());

	// Idle — scheduler will never switch back here
	while (1) SwitchToFiber(tls_schedulerFiber);
}

void WINAPI AcceptLoop(LPVOID param) {

	SOCKET listenSocket = (SOCKET)param;

	while (1) {

		SOCKADDR_IN remoteAddr    = { 0 };
		int         remoteAddrLen = sizeof(remoteAddr);

		SOCKET clientSocket = AsyncAccept(listenSocket, 
			(SOCKADDR*)&remoteAddr, &remoteAddrLen);

		if (clientSocket == INVALID_SOCKET) {
			printf("[AcceptLoop] AsyncAccept failed, retrying...\n");
			continue;
		}

		// Associate the new socket with IOCP
		CreateIoCompletionPort((HANDLE)clientSocket, g_hIOCP, KEY_IO, 0);

		// Allocate a context and spawn a fiber for this connection
		ClientContext* clientContext = HeapAlloc(GetProcessHeap(), 
			HEAP_ZERO_MEMORY, sizeof(ClientContext));

		if (!clientContext) {
			closesocket(clientSocket);
			continue;
		}

		// Convert remote address to a human-readable string
		DWORD remoteHostLen = ArraySize(clientContext->remoteHost);
		WSAAddressToStringW((SOCKADDR*)&remoteAddr, remoteAddrLen,
			NULL, clientContext->remoteHost, &remoteHostLen);

		clientContext->clientSock    = clientSocket;

		LPVOID fiber = CreateFiber(FIBER_STACK_SIZE, HandleClient, clientContext);
		if (!fiber) {
			LOG_ERROR("CreateFiber");
			HeapFree(GetProcessHeap(), 0, clientContext);
			closesocket(clientSocket);
			continue;
		}

		// Kick off the connection fiber
		PostQueuedCompletionStatus(g_hIOCP, 0, KEY_START, fiber);
	}
}

BOOL LoadMSWSockExtensions(SOCKET listenSocket) {

	int iResult = SOCKET_ERROR;
	DWORD dwBytes = 0;

	// Initialize AcceptEx
	GUID guidAcceptEx = WSAID_ACCEPTEX;
	iResult = WSAIoctl(listenSocket, SIO_GET_EXTENSION_FUNCTION_POINTER,
		&guidAcceptEx, sizeof(guidAcceptEx),
		&fnAcceptEx, sizeof(fnAcceptEx),
		&dwBytes, NULL, NULL);

	if (iResult == SOCKET_ERROR) {
		LOG_ERROR("WSAIoctl");
		return FALSE;
	}

	// Initialize GetAcceptExSockaddrs
	GUID guidGetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
	iResult = WSAIoctl(listenSocket, SIO_GET_EXTENSION_FUNCTION_POINTER,
		&guidGetAcceptExSockaddrs, sizeof(guidGetAcceptExSockaddrs),
		&fnGetAcceptExSockaddrs, sizeof(fnGetAcceptExSockaddrs),
		&dwBytes, NULL, NULL);

	if (iResult == SOCKET_ERROR) {
		LOG_ERROR("WSAIoctl");
		return FALSE;
	}

	// Initialize ConnectEx
	GUID guidConnectEx = WSAID_CONNECTEX;
	iResult = WSAIoctl(listenSocket, SIO_GET_EXTENSION_FUNCTION_POINTER,
		&guidConnectEx, sizeof(guidConnectEx),
		&fnConnectEx, sizeof(fnConnectEx),
		&dwBytes, NULL, NULL);

	if (iResult == SOCKET_ERROR) {
		LOG_ERROR("WSAIoctl");
		return FALSE;
	}

	return TRUE;
}

void SchedulerLoop(void) {

	OVERLAPPED_ENTRY entries[BATCH_SIZE];
	ULONG            ulNumEntries;

	while (1) {

		BOOL ok = GetQueuedCompletionStatusEx(
			g_hIOCP, 
			entries, 
			BATCH_SIZE, 
			&ulNumEntries,
			INFINITE, 
			FALSE);

		if (!ok) {
			LOG_ERROR("GetQueuedCompletionStatusEx");
			break;
		}

		for (ULONG i = 0; i < ulNumEntries; i++) {

			OVERLAPPED_ENTRY* e = &entries[i];

			switch (e->lpCompletionKey) {

			case KEY_SHUTDOWN:
				PostQueuedCompletionStatus(g_hIOCP, 0, KEY_SHUTDOWN, NULL);
				return;

			case KEY_START:
				SwitchToFiber(e->lpOverlapped);
				break;

			case KEY_CLEANUP:
				DeleteFiber(e->lpOverlapped);
				break;

			default:
				// Normal I/O completion
				AsyncOp* op = (AsyncOp*)e->lpOverlapped;
				op->bytes = e->dwNumberOfBytesTransferred;
				op->error = RtlNtStatusToDosError((NTSTATUS)op->ov.Internal);
				SwitchToFiber(op->fiber);
				break;
			}
		}
	}
}

BOOL WINAPI CtrlHandler(DWORD dwCtrlType) {
	switch (dwCtrlType) {
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_CLOSE_EVENT:
		PostQueuedCompletionStatus(g_hIOCP, 0, KEY_SHUTDOWN, NULL);
		// suppress default termination
		return TRUE;
	}
	return FALSE;
}

DWORD WINAPI WorkerThread(LPVOID param) {

	UNREFERENCED_PARAMETER(param);

	tls_schedulerFiber = ConvertThreadToFiber(NULL);
	if (!tls_schedulerFiber) {
		LOG_ERROR("ConvertThreadToFiber");
		return 1;
	}

	SchedulerLoop();

	ConvertFiberToThread();
	return 0;
}

int main(void) {

	// Initialize Winsock (Windows Sockets API)
	WSADATA wsaData = { 0 };
	int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != ERROR_SUCCESS) {
		LOG_ERROR_CODE("WSAStartup", err);
		return 1;
	}
	
	// Creates a socket that is bound to a specific transport service provider
	SOCKET listenSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (listenSocket == INVALID_SOCKET) {
		LOG_ERROR("WSASocket");
		return 1;
	}

	// Allow address reuse so we can restart quickly
	BOOL yes = TRUE;
	setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));

	SOCKADDR_IN serverAddr     = { 0 };
	serverAddr.sin_family      = AF_INET;
	serverAddr.sin_port        = htons((USHORT)LISTEN_PORT);
	serverAddr.sin_addr.s_addr = INADDR_ANY;

	// Associates a local address with a socket
	if (bind(listenSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
		LOG_ERROR("bind");
		return 1;
	}

	// Places a socket in a state in which it is listening for an incoming connection
	if (listen(listenSocket, SOMAXCONN) == SOCKET_ERROR) {
		LOG_ERROR("listen");
		return 1;
	}

	printf("Listening on port %d\n", LISTEN_PORT);

	// Load Microsoft-specific extension to the Windows Sockets specification 
	if (LoadMSWSockExtensions(listenSocket) == FALSE) {
		return 1;
	}

	// Creates an I/O completion port and associate the listening socket with the completion port
	// NumberOfConcurrentThreads = 1 (for now)
	g_hIOCP = CreateIoCompletionPort((HANDLE)listenSocket, NULL, KEY_IO, WORKER_THREADS);
	if (g_hIOCP == NULL) {
		LOG_ERROR("CreateIoCompletionPort");
		return 1;
	}

	// Spin up worker threads — each will convert itself to a fiber and run SchedulerLoop
	HANDLE threads[WORKER_THREADS] = { NULL };

	for (DWORD i = 0; i < WORKER_THREADS; i++) {
		threads[i] = CreateThread(NULL, 0, WorkerThread, NULL, 0, NULL);
		if (threads[i] == NULL) {
			LOG_ERROR("CreateThread");
			return 1;
		}
	}

	// Create and kick off the accept fiber
	LPVOID acceptFiber = CreateFiber(FIBER_STACK_SIZE, AcceptLoop, (LPVOID)listenSocket);
	if (!acceptFiber) {
		LOG_ERROR("CreateFiber");
		return 1;
	}

	PostQueuedCompletionStatus(g_hIOCP, 0, KEY_START, acceptFiber);

	SetConsoleCtrlHandler(CtrlHandler, TRUE);

	WaitForMultipleObjects(WORKER_THREADS, threads, TRUE, INFINITE);

	printf("Shutting down\n");

	for (DWORD i = 0; i < WORKER_THREADS; i++) {
		CloseHandle(threads[i]);
	}

	// Clean up
	CloseHandle(g_hIOCP);
	closesocket(listenSocket);
	WSACleanup();
	return 0;
}
