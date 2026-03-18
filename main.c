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

	AsyncRuntimeInit(&rt);

	AsyncRuntimeListen(&rt, ":10080", HandleClient);

	printf("Listening on port %d\n", LISTEN_PORT);

	// Calls AsyncRuntimeShutdown on Ctrl-C
	SetConsoleCtrlHandler(CtrlHandler, TRUE);

	AsyncRuntimeAwait(&rt);

	printf("Shutting down\n");

	AsyncRuntimeCleanup(&rt);

	return 0;
}
