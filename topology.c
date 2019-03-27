#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <time.h>
#include <sys/socket.h> 
#include <arpa/inet.h>
#include <errno.h>

#include "mysnmp.h"

int main(int argc, char *argv[]) 
{ 
	if(argc != 3) {
		fprintf(stderr, "Usage : %s <COMMUNITY STRING> <IP>\n", argv[0]);
		exit(1);
	}

	srand(time(NULL));

	int sock;
	struct sockaddr_in servAddr; 
	MakeUDPSocket(&sock, &servAddr, argv[2]);

////////////////////////////////////////

	int ifNum = GetInterfaceNum(&sock, &servAddr, argv[1]);
	if(ifNum == -1) {
		fprintf(stderr, "GetInterfaceNum() error\n");
		exit(1);
	}

	int *ifIndex = (int*)malloc(sizeof(int)*ifNum);
	if(GetAllInterfaceIndex(&sock, &servAddr, argv[1], ifIndex, ifNum) == -1) {
		fprintf(stderr, "GetInterfaceIndex() error\n");
		exit(1);
	}

	for(int i=0; i<ifNum; i++) 
	{
		int linkStatus;
		GetInterfaceLinkStatus(&sock, &servAddr, argv[1], ifIndex[i], &linkStatus);
		
		if(linkStatus == 1)
		{
			printf("----------------------------------------------------\n");
			printf("index : %d\n", ifIndex[i]);	
			printf("----------------------------------------------------\n");
		}
	}

	free(ifIndex);
	close(sock); 
	return 0; 
}
