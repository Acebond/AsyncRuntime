#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <MSWSock.h>
#include <Windows.h>

#include <stdint.h>
#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")

#define ArraySize(x) (sizeof x / sizeof x[0])

#define LISTEN_PORT     10080
#define BUF_SIZE        4096
#define BATCH_SIZE      64
#define MAX_CONNECTIONS 64

#define FIBER_STACK_SIZE (256 * 1024) // 256 KB

typedef enum {
	KEY_IO,
	KEY_START,
	KEY_CLEANUP,
	KEY_SHUTDOWN,
} OpKey;

typedef enum {
	OP_ACCEPT,
	OP_RECV,
	OP_SEND,
} OpType;

typedef struct {
	OVERLAPPED ov;       // IOCP returns a pointer to this
	LPVOID     fiber;    // Fiber to resume on completion
	DWORD      bytes;    // Bytes transferred
	DWORD      error;    // Win32 error code
	OpType     type;     // Which operation completed
} AsyncOp;

// Per-connection context (lives for the lifetime of one client)
typedef struct {
	SOCKET   clientSock;
	char     recvBuf[BUF_SIZE];
	char     sendBuf[BUF_SIZE];
	DWORD    recvBytes;
} ConnCtx;

LPFN_ACCEPTEX             fnAcceptEx             = NULL;
LPFN_GETACCEPTEXSOCKADDRS fnGetAcceptExSockaddrs = NULL;
LPFN_CONNECTEX            fnConnectEx            = NULL;

BOOL   g_bRunning       = TRUE;
HANDLE g_hIOCP          = NULL;
SOCKET g_listenSocket   = INVALID_SOCKET;
LPVOID g_schedulerFiber = NULL;
int    g_activeConns    = 0;

// ---------------------------------------------------------------------------
// awaitOp — the "await" primitive
// Stores the current fiber in the op, suspends back to the scheduler.
// Execution resumes here once IOCP signals completion.
// ---------------------------------------------------------------------------
void awaitOp(AsyncOp* op) {
	op->fiber = GetCurrentFiber();
	SwitchToFiber(g_schedulerFiber);
	// << resumes here after IOCP fires >>
}

// Issue WSARecv and await its completion
int AsyncRecv(SOCKET sock, char* buf, int len, DWORD* bytesRecv) 
{
	AsyncOp op = { 
		.type = OP_RECV 
	};

	WSABUF wsaBuf = {
		.len = (ULONG)len, 
		.buf = buf 
	};

	DWORD flags = 0;

	int rc = WSARecv(sock, &wsaBuf, 1, NULL, &flags, &op.ov, NULL);
	if (rc == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
		return SOCKET_ERROR;
	}

	// suspend until data arrives
	awaitOp(&op);

	*bytesRecv = op.bytes;
	return (op.error == ERROR_SUCCESS) ? 0 : SOCKET_ERROR;
}

// Issue WSASend and await its completion.
int AsyncSend(SOCKET sock, const char* buf, int len) 
{
	AsyncOp op = {
		.type = OP_SEND,
	};

	WSABUF wsaBuf = { 
		.len = (ULONG)len, 
		.buf = (char*)buf 
	};

	int rc = WSASend(sock, &wsaBuf, 1, NULL, 0, &op.ov, NULL);
	if (rc == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) {
		return SOCKET_ERROR;
	}

	// suspend until send drains
	awaitOp(&op);

	return (op.error == ERROR_SUCCESS) ? 0 : SOCKET_ERROR;
}

// Issue AcceptEx and await its completion.
// AcceptEx requires a pre-created socket for the incoming connection and a
// buffer large enough for two sockaddr_in structs plus 16 bytes each.
BOOL AsyncAccept(SOCKET listenSock, SOCKET* outClientSock) {
	// AcceptEx writes local+remote address into this buffer.
	// The (+16) is a quirk of AcceptEx — it needs 16 bytes of padding per addr.
	char addrBuf[2 * (sizeof(struct sockaddr_in) + 16)] = { 0 };

	// Pre-create the client socket
	SOCKET clientSock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (clientSock == INVALID_SOCKET) {
		printf("[accept] WSASocket failed: %d\n", WSAGetLastError());
		return FALSE;
	}

	AsyncOp op = {
		.type = OP_ACCEPT,
	};

	DWORD bytesReceived = 0;
	BOOL ok = fnAcceptEx(
		listenSock,
		clientSock,
		addrBuf,
		0,                                 // receive 0 bytes of data
		sizeof(SOCKADDR_IN) + 16,          // local addr size
		sizeof(SOCKADDR_IN) + 16,          // remote addr size
		&bytesReceived,
		&op.ov);

	if (!ok && WSAGetLastError() != ERROR_IO_PENDING) {
		printf("[accept] AcceptEx failed: %d\n", WSAGetLastError());
		closesocket(clientSock);
		return FALSE;
	}

	// suspend until a client connects
	awaitOp(&op);

	if (op.error != ERROR_SUCCESS) {
		printf("[accept] completion error: %lu\n", op.error);
		closesocket(clientSock);
		return FALSE;
	}

	// AcceptEx requires this setsockopt so that getpeername() etc. work
	setsockopt(clientSock, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
		(char*)&listenSock, sizeof(listenSock));

	*outClientSock = clientSock;
	return TRUE;
}

void WINAPI HandleClient(LPVOID param) 
{
	ConnCtx* ctx = (ConnCtx*)param;
	SOCKET   sock = ctx->clientSock;

	printf("[Conn %llu] Client connected\n", (UINT64)sock);

	while (1) {
		DWORD bytesRecv = 0;
		int rc = AsyncRecv(sock, ctx->recvBuf, BUF_SIZE - 1, &bytesRecv);

		if (rc == SOCKET_ERROR || bytesRecv == 0) {
			// 0 bytes = graceful close; SOCKET_ERROR = reset
			break;
		}

		ctx->recvBuf[bytesRecv] = '\0';
		printf("[Conn %llu] Recv %lu bytes: %.*s",
			(UINT64)sock, bytesRecv,
			(int)bytesRecv, ctx->recvBuf);

		// Echo back verbatim
		memcpy(ctx->sendBuf, ctx->recvBuf, bytesRecv);
		rc = AsyncSend(sock, ctx->sendBuf, (int)bytesRecv);
		if (rc == SOCKET_ERROR) {
			printf("[Conn %llu] Send error\n", (UINT64)sock);
			break;
		}
	}

	printf("[Conn %llu] Closing\n", (UINT64)sock);
	closesocket(sock);
	HeapFree(GetProcessHeap(), 0, ctx);
	
	g_activeConns--;

	// Signal the scheduler that this fiber is done
	PostQueuedCompletionStatus(g_hIOCP, 0, (ULONG_PTR)KEY_CLEANUP, GetCurrentFiber());

	// Idle — scheduler will never switch back here
	while (1) SwitchToFiber(g_schedulerFiber);
}

// ---------------------------------------------------------------------------
// Accept fiber — loops forever calling asyncAccept, spawning a new
// connection fiber for each client that arrives.
// ---------------------------------------------------------------------------
void WINAPI AcceptLoop(LPVOID param) 
{
	UNREFERENCED_PARAMETER(param);

	printf("[AcceptLoop] Listening on port %d\n", LISTEN_PORT);

	while (1) 
	{
		SOCKET clientSock = INVALID_SOCKET;

		if (!AsyncAccept(g_listenSocket, &clientSock)) {
			printf("[AcceptLoop] AsyncAccept failed, retrying...\n");
			continue;
		}

		if (g_activeConns >= MAX_CONNECTIONS) {
			printf("[AcceptLoop] Too many connections, dropping\n");
			closesocket(clientSock);
			continue;
		}

		// Associate the new socket with IOCP so its recv/send ops complete here
		CreateIoCompletionPort((HANDLE)clientSock, g_hIOCP, 0, 0);

		// Allocate a context and spawn a fiber for this connection
		ConnCtx* ctx = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(ConnCtx));
		if (!ctx) {
			closesocket(clientSock);
			continue;
		}
		ctx->clientSock = clientSock;

		LPVOID fiber = CreateFiber(FIBER_STACK_SIZE, HandleClient, ctx);
		if (!fiber) {
			HeapFree(GetProcessHeap(), 0, ctx);
			closesocket(clientSock);
			continue;
		}

		g_activeConns++;
		printf("[AcceptLoop] Spawned fiber for socket %llu (active: %d)\n",
			(UINT64)clientSock, g_activeConns);

		// Kick off the connection fiber — it will immediately block on asyncRecv
		PostQueuedCompletionStatus(g_hIOCP, 0, KEY_START, (OVERLAPPED*)fiber);
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
		printf("WSAIoctl failed to load AcceptEx with error: %d\n", WSAGetLastError());
		return FALSE;
	}

	// Initialize GetAcceptExSockaddrs
	GUID guidGetAcceptExSockaddrs = WSAID_GETACCEPTEXSOCKADDRS;
	iResult = WSAIoctl(listenSocket, SIO_GET_EXTENSION_FUNCTION_POINTER,
		&guidGetAcceptExSockaddrs, sizeof(guidGetAcceptExSockaddrs),
		&fnGetAcceptExSockaddrs, sizeof(fnGetAcceptExSockaddrs),
		&dwBytes, NULL, NULL);

	if (iResult == SOCKET_ERROR) {
		printf("WSAIoctl failed to load GetAcceptExSockaddrs with error: %d\n", WSAGetLastError());
		return FALSE;
	}

	// Initialize ConnectEx
	GUID guidConnectEx = WSAID_CONNECTEX;
	iResult = WSAIoctl(listenSocket, SIO_GET_EXTENSION_FUNCTION_POINTER,
		&guidConnectEx, sizeof(guidConnectEx),
		&fnConnectEx, sizeof(fnConnectEx),
		&dwBytes, NULL, NULL);

	if (iResult == SOCKET_ERROR) {
		printf("WSAIoctl failed to load ConnectEx with error: %d\n", WSAGetLastError());
		return FALSE;
	}

	return TRUE;
}

void SchedulerLoop(void) {

	OVERLAPPED_ENTRY entries[BATCH_SIZE];
	ULONG            ulNumEntries;

	while (g_bRunning) {

		BOOL ok = GetQueuedCompletionStatusEx(
			g_hIOCP,
			entries,
			ArraySize(entries),
			&ulNumEntries,
			INFINITE,
			FALSE);

		if (!ok) {
			printf("GetQueuedCompletionStatusEx error: %lu\n", GetLastError());
			break;
		}

		for (ULONG i = 0; g_bRunning && (i < ulNumEntries); i++) {

			OVERLAPPED_ENTRY* e = &entries[i];

			switch (e->lpCompletionKey) {

			case KEY_SHUTDOWN:
				printf("[Scheduler] Shutdown signal received\n");
				return;

			case KEY_START:
				SwitchToFiber((LPVOID)e->lpOverlapped);
				break;

			case KEY_CLEANUP:
				DeleteFiber((LPVOID)e->lpOverlapped);
				printf("[Scheduler] fiber deleted (active: %d)\n", g_activeConns);
				break;

			default:
				// Normal I/O completion
				AsyncOp* op = (AsyncOp*)e->lpOverlapped;
				op->bytes = e->dwNumberOfBytesTransferred;
				op->error = ERROR_SUCCESS;
				SwitchToFiber(op->fiber);
				break;
			}
		}
	}
}

int main(void) {

	// Initiates the Winsock (Windows Sockets API) DLL.
	WSADATA wsaData = { 0 };
	int err = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (err != ERROR_SUCCESS) {
		printf("WSAStartup failed with error: %d\n", err);
		return 1;
	}

	// Creates a socket that is bound to a specific transport service provider
	g_listenSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
	if (g_listenSocket == INVALID_SOCKET) {
		printf("WSASocket error: %d\n", WSAGetLastError());
		return 1;
	}

	// Allow address reuse so we can restart quickly
	BOOL yes = TRUE;
	setsockopt(g_listenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&yes, sizeof(yes));

	SOCKADDR_IN serverAddr     = { 0 };
	serverAddr.sin_family      = AF_INET;
	serverAddr.sin_port        = htons((USHORT)LISTEN_PORT);
	serverAddr.sin_addr.s_addr = INADDR_ANY;

	// Associates a local address with a socket
	if (bind(g_listenSocket, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
		printf("bind error: %d\n", WSAGetLastError());
		return 1;
	}

	// Places a socket in a state in which it is listening for an incoming connection
	if (listen(g_listenSocket, SOMAXCONN) == SOCKET_ERROR) {
		printf("listen error: %d\n", WSAGetLastError());
		return 1;
	}

	// Load Microsoft-specific extension to the Windows Sockets specification 
	if (LoadMSWSockExtensions(g_listenSocket) == FALSE) {
		return 1;
	}

	// Creates an I/O completion port and associate the listening socket with the completion port
	// NumberOfConcurrentThreads = 1 (for now)
	g_hIOCP = CreateIoCompletionPort((HANDLE)g_listenSocket, NULL, (ULONG_PTR)g_listenSocket, 1);
	if (g_hIOCP == NULL) {
		printf("CreateIoCompletionPort error: %lu\n", GetLastError());
		return 1;
	}

	// Convert main thread to a fiber (required before using fibers)
	g_schedulerFiber = ConvertThreadToFiber(NULL);
	if (!g_schedulerFiber) {
		printf("ConvertThreadToFiber error: %lu\n", GetLastError());
		return 1;
	}


	// Create and kick off the accept fiber
	// It will call AsyncAccept, which suspends immediately back here
	LPVOID acceptFiber = CreateFiber(FIBER_STACK_SIZE, AcceptLoop, NULL);
	if (!acceptFiber) {
		printf("CreateFiber failed\n");
		return 1;
	}

	PostQueuedCompletionStatus(g_hIOCP, 0, KEY_START, (OVERLAPPED*)acceptFiber);
	SchedulerLoop();

	// Clean up
	CloseHandle(g_hIOCP);
	closesocket(g_listenSocket);
	WSACleanup();
	ConvertFiberToThread();
	return 0;
}
