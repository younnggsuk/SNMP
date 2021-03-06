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

	printf("----------------------------------------------------\n");
	printf("Number of Interfaces : %d \n", ifNum);
	printf("----------------------------------------------------\n");


	for(int i=0; i<ifNum; i++) 
	{
		int linkStatus;
		GetInterfaceLinkStatus(&sock, &servAddr, argv[1], ifIndex[i], &linkStatus);
		
		if(linkStatus == 1)
		{
			printf("     Interface %d's Information\n", i+1);
			printf("----------------------------------------------------\n");
			GetInterfaceDesc(&sock, &servAddr, argv[1], ifIndex[i]);
			GetInterfaceMacAddr(&sock, &servAddr, argv[1], ifIndex[i]);
			GetInterfaceMTU(&sock, &servAddr, argv[1], ifIndex[i]);
			GetInterfaceBandwidth(&sock, &servAddr, argv[1], ifIndex[i]);
			GetInterfaceInOctet(&sock, &servAddr, argv[1], ifIndex[i]);
			GetInterfaceOutOctet(&sock, &servAddr, argv[1], ifIndex[i]);
			printf("----------------------------------------------------\n");
		}
	}

	free(ifIndex);
	close(sock); 
	return 0; 
}

/* print packet in hexa

	for(int i=0; i<(index/4); i++)
	{
		for(int j=0; j<4; j++)
		{
			printf("%02x", requestPacket[j+(i*4)]);
		}
		printf("\n");
	}

*/

/*  print Data

	int index = 0;
	int type = recvData[index++];
	int len = recvData[index++];
	if(type == 2)
	{
		for(int i=0; i<len; i++)
		{
			printf("%d", recvData[index++]);
		}
	}
	else if(type == 4)
	{
		for(int i=0; i<len; i++)
		{
			printf("%c", recvData[index++]);
		}
	}

	printf("\n");

*/


/* 32bit rand num

   u_int MakeRandRequestId()
	{
		u_short num = rand();
		u_int reqId = (u_int)( (num<<16) | rand() );
	
		return reqId;
	}

*/
