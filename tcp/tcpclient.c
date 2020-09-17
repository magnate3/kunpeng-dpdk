#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main() {
	const char* server_name = "10.10.103.229";
	const int server_port = 80;

	struct sockaddr_in server_address;
	memset(&server_address, 0, sizeof(server_address));
	server_address.sin_family = AF_INET;

	// creates binary representation of server name
	// and stores it as sin_addr
	// http://beej.us/guide/bgnet/output/html/multipage/inet_ntopman.html
	//inet_pton(AF_INET, server_name, &server_address.sin_addr);
        server_address.sin_family 	= AF_INET;
        server_address.sin_addr.s_addr = inet_addr("10.10.103.229");

	// htons: port in network order format
	server_address.sin_port = htons(server_port);
        bzero(&(server_address.sin_zero),8);

	// open a stream socket
	int sock;
	if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		printf("could not create socket\n");
		return 1;
	}
        

	// TCP is connection oriented, a reliable connection
	// **must** be established before any data is exchanged
	if (connect(sock, (struct sockaddr*)&server_address,
	            sizeof(server_address)) < 0) {
	    close(sock);
		printf("could not connect to server\n");
		return 1;
	}
    else
    {
		printf("could  connect to server\n");
    }

	// send

	// data that will be sent to the server
	const char* data_to_send = "Gangadhar Hi Shaktimaan hai";
	if (send(sock, data_to_send, strlen(data_to_send), 0) <= 0)
	{
		printf("could not connect to server\n");
	    close(sock);
		return 1;
	}
    else
    {
		printf("send data to  server succ\n");
    }
	// receive

	int n = 0;
	int len = 0, maxlen = 100;
	char buffer[maxlen];
	char* pbuffer = buffer;

	// will remain open until the server terminates the connection
	while (1) {
	    if ((n = recv(sock, pbuffer, maxlen, 0)) > 0)
	    {
		printf("received data\n");
		pbuffer += n;
		maxlen -= n;
		len += n;

		buffer[len] = '\0';
		printf("received: '%s'\n", buffer);
		}
		else if (n < 0)
		{
		    printf("received data fail \n");
			break;
		}
		else 
		{
		    printf("received zero  data  \n");
			break;
		}
	}

	// close the socket
	close(sock);
	return 0;
}
