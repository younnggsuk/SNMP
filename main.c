#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <time.h>
#include <sys/socket.h> 
#include <arpa/inet.h>
#include <errno.h>

#include "func.h"

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
	
	char *community = (char*)malloc(strlen(argv[1])+1);
	strcpy(community, argv[1]);
	community[strlen(argv[1])] = '\0';

	int ifNum = GetInterfaceNum(&sock, &servAddr, community);
	if(ifNum == -1) {
		fprintf(stderr, "GetInterfaceNum() error\n");
	}

	int *ifIndex = (int*)malloc(sizeof(int)*ifNum);
	if(GetInterfaceIndex(&sock, &servAddr, community, ifIndex, ifNum) == -1) {
		fprintf(stderr, "GetInterfaceIndex() error\n");
	}

	printf("----------------------------------------------------\n");
	printf("Number of Interfaces : %d \n", ifNum);
	printf("----------------------------------------------------\n");


	for(int i=0; i<ifNum; i++) {
		printf("     Interface %d's Information\n", i+1);
		printf("----------------------------------------------------\n");
		GetInterfaceDesc(&sock, &servAddr, community, ifIndex[i]);
		GetInterfaceMacAddr(&sock, &servAddr, community, ifIndex[i]);
		GetInterfaceMTU(&sock, &servAddr, community, ifIndex[i]);
		GetInterfaceBandwidth(&sock, &servAddr, community, ifIndex[i]);
		GetInterfaceInOctet(&sock, &servAddr, community, ifIndex[i]);
		GetInterfaceOutOctet(&sock, &servAddr, community, ifIndex[i]);
		printf("----------------------------------------------------\n");
	}

	free(community);
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
