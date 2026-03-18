#include "AsyncRuntime.h"

#define RECV_BUF_SIZE 4096

AsyncRuntime rt;

BOOL WINAPI CtrlHandler(DWORD dwCtrlType) {
	switch (dwCtrlType) {
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
	case CTRL_CLOSE_EVENT:
		AsyncRuntimeShutdown(&rt);
		return TRUE;
	}
	return FALSE;
}

void HandleClient(SOCKET socket) 
{
	CHAR recvBuf[RECV_BUF_SIZE];

	while (1) {
		DWORD bytesRecv = 0;
		int rc = AsyncRecv(socket, recvBuf, RECV_BUF_SIZE - 1, &bytesRecv);

		if (rc == SOCKET_ERROR || bytesRecv == 0) {
			// 0 bytes = graceful close; SOCKET_ERROR = reset
			break;
		}

		rc = AsyncSend(socket, recvBuf, bytesRecv);
		if (rc == SOCKET_ERROR) {
			break;
		}
	}

	closesocket(socket);
}

int main(void) {

	const WCHAR* host = L"127.0.0.1";
	const USHORT port = 10080;

	AsyncRuntimeInit(&rt);

	AsyncRuntimeListen(&rt, host, port, HandleClient);

	printf("Listening on port %d\n", port);

	// Calls AsyncRuntimeShutdown on Ctrl-C
	SetConsoleCtrlHandler(CtrlHandler, TRUE);

	// Waits until AsyncRuntimeShutdown is called 
	AsyncRuntimeAwait(&rt);

	printf("Shutting down\n");

	AsyncRuntimeCleanup(&rt);

	return 0;
}
