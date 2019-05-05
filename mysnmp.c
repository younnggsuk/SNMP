#include <stdio.h> 
#include <stdlib.h> 
#include <unistd.h> 
#include <string.h> 
#include <time.h>
#include <sys/socket.h> 
#include <arpa/inet.h>
#include <errno.h>

#include "mysnmp.h"

/*
 	Socket
 */
void MakeUDPSocket(int *sock, struct sockaddr_in *servAddr, char *ipAddr)
{
	if((*sock = socket(AF_INET, SOCK_DGRAM, 0)) < -1) {
		fprintf(stderr, "socket() error\n");
		exit(1); 
	} 
	memset(servAddr, 0, sizeof(*servAddr)); 

	servAddr->sin_family = AF_INET; 
	servAddr->sin_port = htons(PORT_SNMP); 
	servAddr->sin_addr.s_addr = inet_addr(ipAddr);
	
	connect(*sock, (struct sockaddr*)servAddr, sizeof(*servAddr));
}

/*
 	SNMP Get-request
 */
int MakeSnmpGetRequest(u_char requestPacket[], char *community, u_int oid[], int oidLen, u_int reqId)
{
	int commLen = strlen(community);
	int index = 0;

	memset(requestPacket, '\0', BUF_MAX);

	// ASN.1 Header
	requestPacket[index++] = 0x30;

	// PDU_length (total length)
	requestPacket[index++] = 0x1a + commLen + oidLen;

	// SNMP version
	requestPacket[index++] = 0x02; 		// integer(2) 
	requestPacket[index++] = 0x01; 		// length = 1
	requestPacket[index++] = 0x01; 		// snmp v2c (v1 : 0x00)

	// Community information
	requestPacket[index++] = 0x04;				  	  // string(4)
	requestPacket[index++] = commLen; 				  // community len
	memcpy(&requestPacket[index], community, commLen); // community string
	index += commLen;

	// SNMP GET request
	requestPacket[index++] = 0xa0; 		// request type (0xa0)
	requestPacket[index++] = oidLen+19;  // request length
	
	// Request ID
	requestPacket[index++] = 0x02;
	requestPacket[index++] = 0x04;
	requestPacket[index++] = (u_char)((reqId>>24) & 0xff);
	requestPacket[index++] = (u_char)((reqId>>16) & 0xff);
	requestPacket[index++] = (u_char)((reqId>>8) & 0xff);
	requestPacket[index++] = (u_char)((reqId>>0) & 0xff);

	// Error status
	requestPacket[index++] = 0x02; 		// Integer(2)
	requestPacket[index++] = 0x01; 		// len(1)
	requestPacket[index++] = 0x00; 		// Error status(0)

	// Error index
	requestPacket[index++] = 0x02; 		// Integer(2)
	requestPacket[index++] = 0x01; 		// len(1)
	requestPacket[index++] = 0x00; 		// Error index(0)

	// Variable Binding sequence
	requestPacket[index++] = 0x30; 		// variable binding start
	requestPacket[index++] = oidLen+5; 	// variable binding sequence len

	// First Variable Binding sequence
	requestPacket[index++] = 0x30;		// first variable binding sequence start
	requestPacket[index++] = oidLen+3; 	// first variable binding sequence len

	// Object ID
	requestPacket[index++] = 0x06; 		// object type
	requestPacket[index++] = oidLen-1; 	// OID len after 1.
	requestPacket[index++] = 0x2b; 		// start of OID(replace 1.3)
	
	for(int i=0; i<oidLen-2; i++) {
		requestPacket[index++] = (u_char)(oid[i+2]);
	}

	// End of SNMP Get-request
	requestPacket[index++] = 0x05;
	requestPacket[index++] = 0x00;

	return index;
}

/*
 	SNMP Get-next-request
 */
int MakeSnmpGetNextRequest(u_char requestPacket[], char *community, u_int oid[], int oidLen, u_int reqId)
{
	int commLen = strlen(community);
	int index = 0;

	memset(requestPacket, '\0', BUF_MAX);

	// ASN.1 Header
	requestPacket[index++] = 0x30;

	// PDU_length (total length)
	requestPacket[index++] = 0x1a + commLen + oidLen;

	// SNMP version
	requestPacket[index++] = 0x02; 		// integer(2) 
	requestPacket[index++] = 0x01; 		// length = 1
	requestPacket[index++] = 0x01; 		// snmp v2c (v1 : 0x00)

	// Community information
	requestPacket[index++] = 0x04;				  	  // string(4)
	requestPacket[index++] = commLen; 				  // community len
	memcpy(&requestPacket[index], community, commLen); // community string
	index += commLen;

	// SNMP GET request
	requestPacket[index++] = 0xa1; 		// request type (0xa1)
	requestPacket[index++] = oidLen+19;  // request length
	
	// Request ID
	requestPacket[index++] = 0x02;
	requestPacket[index++] = 0x04;
	requestPacket[index++] = (u_char)((reqId>>24) & 0xff);
	requestPacket[index++] = (u_char)((reqId>>16) & 0xff);
	requestPacket[index++] = (u_char)((reqId>>8) & 0xff);
	requestPacket[index++] = (u_char)((reqId>>0) & 0xff);

	// Error status
	requestPacket[index++] = 0x02; 		// Integer(2)
	requestPacket[index++] = 0x01; 		// len(1)
	requestPacket[index++] = 0x00; 		// Error status(0)

	// Error index
	requestPacket[index++] = 0x02; 		// Integer(2)
	requestPacket[index++] = 0x01; 		// len(1)
	requestPacket[index++] = 0x00; 		// Error index(0)

	// Variable Binding sequence
	requestPacket[index++] = 0x30; 		// variable binding start
	requestPacket[index++] = oidLen+5; 	// variable binding sequence len

	// First Variable Binding sequence
	requestPacket[index++] = 0x30;		// first variable binding sequence start
	requestPacket[index++] = oidLen+3; 	// first variable binding sequence len

	// Object ID
	requestPacket[index++] = 0x06; 		// object type
	requestPacket[index++] = oidLen-1; 	// OID len after 1.
	requestPacket[index++] = 0x2b; 		// start of OID(replace 1.3)
	
	for(int i=0; i<oidLen-2; i++) {
		requestPacket[index++] = (u_char)(oid[i+2]);
	}

	// End of SNMP Get-next-request
	requestPacket[index++] = 0x05;
	requestPacket[index++] = 0x00;

	return index;
}

int ConvertOID(char *oidStr, u_int oid[])
{
	int oidLen = 0;
	char *tmp = (char*)malloc(strlen(oidStr)+1);
	if(tmp == NULL)
	{
		fprintf(stderr, "malloc() error\n");
		exit(1);
	}
	strcpy(tmp, oidStr);

	char *token = strtok(tmp, ".");

	while(token != NULL)
	{
		oid[oidLen++] = (u_int)atoi(token);
		token = strtok(NULL, ".");
	}
	free(tmp);

	return oidLen;
}

/* 
    SNMP Get-response
 */
int ParseSnmpGetResponse(u_char responsePacket[], int recvLen, u_char recvData[], u_int reqId)
{
	int index = 0;

	if(ParseAsnHeader(responsePacket, &index) == -1)			{ return -1; }
	if(ParsePduLength(responsePacket, recvLen, &index) == -1)	{ return -1; }
	if(ParseVersion(responsePacket, &index) == -1) 				{ return -1; }
	if(ParseCommunity(responsePacket, &index) == -1) 			{ return -1; }
	if(ParseResponse(responsePacket, recvLen, &index) == -1)	{ return -1; }
	if(ParseRequestId(responsePacket, &index, reqId) == -1) 	{ return -1; }
	if(ParseErrorStatus(responsePacket,&index) == -1) 			{ return -1; }
	if(ParseErrorIndex(responsePacket, &index) == -1) 		 	{ return -1; }
	if(ParseVarBindingSequence(responsePacket, &index) == -1)	{ return -1; }
	if(ParseOID(responsePacket, &index) == -1) 					{ return -1; }

	// Data copy
	memcpy(recvData, &(responsePacket[(index)]), (responsePacket[(index)+1]+2));
	return 0;
}
int ParseAsnHeader(u_char responsePacket[], int *index)
{
	if(responsePacket[(*index)++] == 0x30) {
		//printf("ASN header : %x\n", responsePacket[(*index)-1]);
		return 0;
	}

	fprintf(stderr, "Parse ASN Header Error\n");
	return -1;
}
int ParsePduLength(u_char responsePacket[], int recvLen, int *index)
{

	if(responsePacket[(*index)++] == (recvLen-2)) {
		//printf("PDU length : %d, recvLen : %d\n", responsePacket[(*index)-1], recvLen-2);
		
		return 0;
	}
	else if(responsePacket[(*index)++] == (recvLen-3))
	{
		return 0;
	}

	fprintf(stderr, "Parse PDU Length Error\n");
	return -1;
}
int ParseVersion(u_char responsePacket[], int *index)
{
	if(responsePacket[(*index)++] == 0x02) {
		if(responsePacket[(*index)++] == 0x01) {
			if(responsePacket[(*index)++] == 0x01) {
				//printf("SNMP Version : 2\n");
				return 0;
			}
		}
	}
	
	fprintf(stderr, "Parse Version Error\n");
	return -1;
}
int ParseCommunity(u_char responsePacket[], int *index)
{
	if(responsePacket[(*index)++] == 0x04) 
	{
		int commLen = responsePacket[(*index)++];

		//printf("Community : "); 	
		for(int i=0; i<commLen; i++) {
			(*index)++;
			//printf("%c", responsePacket[(*index)++]);
		}
		//printf("\n");
		return 0;
	}
	
	fprintf(stderr, "Parse Community Error\n");
	return -1;
}
int ParseResponse(u_char responsePacket[], int recvLen, int *index)
{
	if(responsePacket[(*index)++] == 0xa2)
	{
		int len = responsePacket[(*index)++];
		if(len == (recvLen-(*index)))
			return 0;
	}

	fprintf(stderr, "Parse Response Error\n");
	return -1;
}
int ParseRequestId(u_char responsePacket[], int *index, u_int reqId)
{
	if(responsePacket[(*index)++] == 0x02) 
	{
		int idLen = responsePacket[(*index)++];
		u_char *buf = (u_char*)malloc(idLen);

		for(int i=0; i<idLen; i++) {
			buf[idLen-i-1] = responsePacket[(*index)++];
		}
	
		// check request id
		if(*((u_int*)buf) != reqId) {
			return -1;
		}

		free(buf);
		return 0;
	}
	
	fprintf(stderr, "Parse Request ID Error\n");
	return -1;
}
int ParseErrorStatus(u_char responsePacket[], int *index)
{
	if(responsePacket[(*index)++] == 0x02)
	{
		int errLen = responsePacket[(*index)++];
		u_char *buf = (u_char*)(malloc(errLen));

		for(int i=0; i<errLen; i++)	{
			buf[errLen-i-1] = responsePacket[(*index)++];
		}
		//printf("Error status : %u\n", *((u_int*)buf));
		free(buf);
		return 0;
	}

	fprintf(stderr, "Parse Error-Status Error\n");
	return -1;
}
int ParseErrorIndex(u_char responsePacket[], int *index)
{
	if(responsePacket[(*index)++] == 0x02)
	{
		int errLen = responsePacket[(*index)++];
		u_char *buf = (u_char*)(malloc(errLen));

		for(int i=0; i<errLen; i++)	{
			buf[errLen-i-1] = responsePacket[(*index)++];
		}
		//printf("Error Index : %u\n", *((u_int*)buf));
		free(buf);
		return 0;
	}

	fprintf(stderr, "Parse Error-Index Error\n");
	return -1;
}
int ParseVarBindingSequence(u_char responsePacket[], int *index)
{
	if(responsePacket[(*index)++] == 0x30) 
	{
		int vbSeqLen = responsePacket[(*index)++];
		if(responsePacket[(*index)++] == 0x30)
		{
			int vbSeqLenFirst = responsePacket[(*index)++];
			if( (vbSeqLen-vbSeqLenFirst) == 2)
				return 0;	
		}
	}

	fprintf(stderr, "Parse Variable Binding Sequence Error\n");
	return -1;
}
int ParseOID(u_char responsePacket[], int *index)
{
	if(responsePacket[(*index)++] == 0x06)
	{
		int oidLen = responsePacket[(*index)++];
		if(responsePacket[(*index)++] == 0x2b)
		{
			//printf("OID : 1.3.");
			for(int i=0; i<oidLen-2; i++) {
				(*index)++;
				//printf("%d.", responsePacket[(*index)++]);
			}
			(*index)++;
			//printf("%d\n", responsePacket[(*index)++]);
			return 0;
		}
	}

	fprintf(stderr, "Parse OID Error\n");
	return -1;
}

/*
	Get Interface Number
 */
int GetInterfaceNum(int *sock, struct sockaddr_in *servAddr, char *community)
{
	int packetLen, oidLen, recvLen;
	u_int  addrLen;
	u_char requestPacket[BUF_MAX] = { '\0', };
	u_char responsePacket[BUF_MAX] = { '\0', };
	u_char recvData[BUF_MAX] = { '\0', };
	u_int reqId = rand();

	addrLen = sizeof(*servAddr);
	u_int oid[OID_MAX] = { 0, };
	oidLen = ConvertOID(OID_INTERFACE_NUM, oid);

	packetLen = MakeSnmpGetRequest(requestPacket, community, oid, oidLen, reqId);
	sendto(*sock, requestPacket, packetLen, 0, (struct sockaddr*)servAddr, sizeof(*servAddr)); 
	recvLen = recvfrom(*sock, responsePacket, BUF_MAX, 0, (struct sockaddr*)servAddr, &addrLen);

	if(recvLen < 0) {
		printf("recvfrom() error\n");
	}

	if(ParseSnmpGetResponse(responsePacket, recvLen, recvData, reqId) < 0) {
		printf("ParseSnmpGetResponse() Error \n");
	}
	
	if(recvData[0] == 2) {
		if(recvData[1] == 1) {
			return (int)recvData[2];
		}
	}

	return -1;
}

/*
	Get All Interface Index
 */
int GetAllInterfaceIndex(int *sock, struct sockaddr_in *servAddr, char *community, int *indexArr, int ifNum)
{
	int packetLen, oidLen, recvLen;
	u_int  addrLen;
	u_char requestPacket[BUF_MAX] = { '\0', };
	u_char responsePacket[BUF_MAX] = { '\0', };
	u_char recvData[BUF_MAX] = { '\0', };
	u_int reqId = rand();

	addrLen = sizeof(*servAddr);
	u_int oid[OID_MAX] = { 0, };
	oidLen = ConvertOID(OID_INTERFACE_INDEX, oid);

	for(int i=0; i<ifNum; i++)
	{
		packetLen = MakeSnmpGetNextRequest(requestPacket, community, oid, oidLen, reqId);
		sendto(*sock, requestPacket, packetLen, 0, (struct sockaddr*)servAddr, sizeof(*servAddr)); 
		recvLen = recvfrom(*sock, responsePacket, BUF_MAX, 0, (struct sockaddr*)servAddr, &addrLen);

		if(recvLen < 0) {
			printf("recvfrom() error\n");
		}

		if(ParseSnmpGetResponse(responsePacket, recvLen, recvData, reqId) < 0) {
			printf("ParseSnmpGetResponse() Error \n");
		}
	
		int index = 0;
		int type = recvData[index++];
		int len = recvData[index++];
		if(type == 2)
		{
			if(len == 1)
			{
				indexArr[i] = recvData[2];
				oidLen = ConvertOID(OID_INTERFACE_INDEX, oid);
				oid[oidLen++] = recvData[2];
				reqId++;
				continue;
			}
		}
		return -1;
	}
	return 0;
}

/*
	Get Interface Descriptor
 */
void GetInterfaceDesc(int *sock, struct sockaddr_in *servAddr, char *community, int ifIndex)
{
	int packetLen, oidLen, recvLen;
	u_int  addrLen;
	u_char requestPacket[BUF_MAX] = { '\0', };
	u_char responsePacket[BUF_MAX] = { '\0', };
	u_char recvData[BUF_MAX] = { '\0', };
	u_int reqId = rand();

	addrLen = sizeof(*servAddr);
	u_int oid[OID_MAX] = { 0, };
	oidLen = ConvertOID(OID_INTERFACE_DESC, oid);
	oid[oidLen++] = (u_int)ifIndex;

	packetLen = MakeSnmpGetRequest(requestPacket, community, oid, oidLen, reqId);
	sendto(*sock, requestPacket, packetLen, 0, (struct sockaddr*)servAddr, sizeof(*servAddr));
	recvLen = recvfrom(*sock, responsePacket, BUF_MAX, 0, (struct sockaddr*)servAddr, &addrLen); 

	if(recvLen < 0) {
		printf("recvfrom() error\n");
	}

	if(ParseSnmpGetResponse(responsePacket, recvLen, recvData, reqId) < 0) {
		printf("ParseSnmpGetResponse() Error \n");
	}

	int index = 0;
	int type = recvData[index++];
	int len = recvData[index++];
	if(type == 0x04)
	{
		printf("Interface : ");
		for(int i=0; i<len; i++)
		{
			printf("%c", recvData[index++]);
		}
	}
	printf("\n");
}

/*
	Get Interface MTU
 */
void GetInterfaceMTU(int *sock, struct sockaddr_in *servAddr, char *community, int ifIndex)
{
	int packetLen, oidLen, recvLen;
	u_int  addrLen;
	u_char requestPacket[BUF_MAX] = { '\0', };
	u_char responsePacket[BUF_MAX] = { '\0', };
	u_char recvData[BUF_MAX] = { '\0', };
	u_int reqId = rand();

	addrLen = sizeof(*servAddr);
	u_int oid[OID_MAX] = { 0, };
	oidLen = ConvertOID(OID_INTERFACE_MTU, oid);
	oid[oidLen++] = (u_int)ifIndex;

	packetLen = MakeSnmpGetRequest(requestPacket, community, oid, oidLen, reqId);
	sendto(*sock, requestPacket, packetLen, 0, (struct sockaddr*)servAddr, sizeof(*servAddr)); 
	recvLen = recvfrom(*sock, responsePacket, BUF_MAX, 0, (struct sockaddr*)servAddr, &addrLen); 
	
	if(recvLen < 0) {
		printf("recvfrom() error\n");
	}

	if(ParseSnmpGetResponse(responsePacket, recvLen, recvData, reqId) < 0) {
		printf("ParseSnmpGetResponse() Error \n");
	}

	int index = 0;
	int type = recvData[index++];
	int len = recvData[index++];
	if(type == 0x02)
	{
		u_char *mtu = (u_char*)malloc(len);
		for(int i=0; i<len; i++) {
			mtu[len-i-1] = recvData[index++];
		}

		printf("MTU       : %10d\t[octets]\n", *((int*)&mtu[0]));
		free(mtu);
	}
}

/*
	Get Interface Bandwidth
 */
void GetInterfaceBandwidth(int *sock, struct sockaddr_in *servAddr, char *community, int ifIndex)
{
	int packetLen, oidLen, recvLen;
	u_int  addrLen;
	u_char requestPacket[BUF_MAX] = { '\0', };
	u_char responsePacket[BUF_MAX] = { '\0', };
	u_char recvData[BUF_MAX] = { '\0', };
	u_int reqId = rand();

	addrLen = sizeof(*servAddr);
	u_int oid[OID_MAX] = { 0, };
	oidLen = ConvertOID(OID_INTERFACE_BANDWIDTH, oid);
	oid[oidLen++] = (u_int)ifIndex;

	packetLen = MakeSnmpGetRequest(requestPacket, community, oid, oidLen, reqId);
	sendto(*sock, requestPacket, packetLen, 0, (struct sockaddr*)servAddr, sizeof(*servAddr)); 
	recvLen = recvfrom(*sock, responsePacket, BUF_MAX, 0, (struct sockaddr*)servAddr, &addrLen); 
	
	if(recvLen < 0) {
		printf("recvfrom() error\n");
	}

	if(ParseSnmpGetResponse(responsePacket, recvLen, recvData, reqId) < 0) {
		printf("ParseSnmpGetResponse() Error \n");
	}
	
	int index = 0;
	int type = recvData[index++];
	int len = recvData[index++];
	if(type == 0x42)
	{
		u_char *bandWidth = (u_char*)malloc(len);
		for(int i=0; i<len; i++) {
			bandWidth[len-i-1] = recvData[index++];
		}

		printf("Bandwidth : %10d\t[bits/sec]\n", *((int*)&bandWidth[0]));
		free(bandWidth);
	}
}

/*
	Get Interface LinkStatus
 */
void GetInterfaceLinkStatus(int *sock, struct sockaddr_in *servAddr, char *community, int ifIndex, int *state)
{
	int packetLen, oidLen, recvLen;
	u_int  addrLen;
	u_char requestPacket[BUF_MAX] = { '\0', };
	u_char responsePacket[BUF_MAX] = { '\0', };
	u_char recvData[BUF_MAX] = { '\0', };
	u_int reqId = rand();

	addrLen = sizeof(*servAddr);
	u_int oid[OID_MAX] = { 0, };
	oidLen = ConvertOID(OID_INTERFACE_LINK_STATUS, oid);
	oid[oidLen++] = (u_int)ifIndex;

	packetLen = MakeSnmpGetRequest(requestPacket, community, oid, oidLen, reqId);
	sendto(*sock, requestPacket, packetLen, 0, (struct sockaddr*)servAddr, sizeof(*servAddr)); 
	recvLen = recvfrom(*sock, responsePacket, BUF_MAX, 0, (struct sockaddr*)servAddr, &addrLen); 
	
	if(recvLen < 0) {
		printf("recvfrom() error\n");
	}

	if(ParseSnmpGetResponse(responsePacket, recvLen, recvData, reqId) < 0) {
		printf("ParseSnmpGetResponse() Error \n");
	}

	int index = 0;
	int type = recvData[index++];
	int len = recvData[index++];
	if(type == 0x02)
	{
		if(len == 0x01)
		{
			*state = recvData[index];
		}
	}
}

/*
	Get Interface InOctets
 */
void GetInterfaceInOctet(int *sock, struct sockaddr_in *servAddr, char *community, int ifIndex)
{
	int packetLen, oidLen, recvLen;
	u_int  addrLen;
	u_char requestPacket[BUF_MAX] = { '\0', };
	u_char responsePacket[BUF_MAX] = { '\0', };
	u_char recvData[BUF_MAX] = { '\0', };
	u_int reqId = rand();

	addrLen = sizeof(*servAddr);
	u_int oid[OID_MAX] = { 0, };
	oidLen = ConvertOID(OID_INTERFACE_IN_OCTETS, oid);
	oid[oidLen++] = (u_int)ifIndex;

	packetLen = MakeSnmpGetRequest(requestPacket, community, oid, oidLen, reqId);
	sendto(*sock, requestPacket, packetLen, 0, (struct sockaddr*)servAddr, sizeof(*servAddr)); 
	recvLen = recvfrom(*sock, responsePacket, BUF_MAX, 0, (struct sockaddr*)servAddr, &addrLen); 
	
	if(recvLen < 0) {
		printf("recvfrom() error\n");
	}

	if(ParseSnmpGetResponse(responsePacket, recvLen, recvData, reqId) < 0) {
		printf("ParseSnmpGetResponse() Error \n");
	}
	
	int index = 0;
	int type = recvData[index++];
	int len = recvData[index++];
	if(type == 0x41)
	{
		u_char *inOctet = (u_char*)malloc(len);
		for(int i=0; i<len; i++) {
			inOctet[len-i-1] = recvData[index++];
		}

		printf("InOctets  : %10d\t[octets/sec]\n", *((int*)&inOctet[0]));
		free(inOctet);
	}
}

/*
	Get Interface OutOctets
 */
void GetInterfaceOutOctet(int *sock, struct sockaddr_in *servAddr, char *community, int ifIndex)
{
	int packetLen, oidLen, recvLen;
	u_int  addrLen;
	u_char requestPacket[BUF_MAX] = { '\0', };
	u_char responsePacket[BUF_MAX] = { '\0', };
	u_char recvData[BUF_MAX] = { '\0', };
	u_int reqId = rand();

	addrLen = sizeof(*servAddr);
	u_int oid[OID_MAX] = { 0, };
	oidLen = ConvertOID(OID_INTERFACE_OUT_OCTETS, oid);
	oid[oidLen++] = (u_int)ifIndex;

	packetLen = MakeSnmpGetRequest(requestPacket, community, oid, oidLen, reqId);
	sendto(*sock, requestPacket, packetLen, 0, (struct sockaddr*)servAddr, sizeof(*servAddr)); 
	recvLen = recvfrom(*sock, responsePacket, BUF_MAX, 0, (struct sockaddr*)servAddr, &addrLen); 
	
	if(recvLen < 0) {
		printf("recvfrom() error\n");
	}

	if(ParseSnmpGetResponse(responsePacket, recvLen, recvData, reqId) < 0) {
		printf("ParseSnmpGetResponse() Error \n");
	}
	
	int index = 0;
	int type = recvData[index++];
	int len = recvData[index++];
	if(type == 0x41)
	{
		u_char *outOctet = (u_char*)malloc(len);
		for(int i=0; i<len; i++) {
			outOctet[len-i-1] = recvData[index++];
		}

		printf("OutOctets : %10d\t[octets/sec]\n", *((int*)&outOctet[0]));
		free(outOctet);
	}
}

/*
	Get Interface MAC-Address
 */
void GetInterfaceMacAddr(int *sock, struct sockaddr_in *servAddr, char *community, int ifIndex)
{
	int packetLen, oidLen, recvLen;
	u_int  addrLen;
	u_char requestPacket[BUF_MAX] = { '\0', };
	u_char responsePacket[BUF_MAX] = { '\0', };
	u_char recvData[BUF_MAX] = { '\0', };
	u_int reqId = rand();

	addrLen = sizeof(*servAddr);
	u_int oid[OID_MAX] = { 0, };
	oidLen = ConvertOID(OID_INTERFACE_MAC_ADDR, oid);
	oid[oidLen++] = (u_int)ifIndex;

	packetLen = MakeSnmpGetRequest(requestPacket, community, oid, oidLen, reqId);
	sendto(*sock, requestPacket, packetLen, 0, (struct sockaddr*)servAddr, sizeof(*servAddr)); 
	recvLen = recvfrom(*sock, responsePacket, BUF_MAX, 0, (struct sockaddr*)servAddr, &addrLen); 
	
	if(recvLen < 0) {
		printf("recvfrom() error\n");
	}

	if(ParseSnmpGetResponse(responsePacket, recvLen, recvData, reqId) < 0) {
		printf("ParseSnmpGetResponse() Error \n");
	}

	int index = 0;
	int type = recvData[index++];
	int len = recvData[index++];
	if(type == 0x04)
	{
		printf("Mac Addr  : ");
		if(len > 0)
		{
			for(int i=0; i<len-1; i++)
			{
				printf("%02x:", recvData[index++]);
			}
			printf("%02x", recvData[index++]);
		}
	}
	printf("\n");
}

///*
//	Get All IP Address
// */
//int GetAllIpAddress(int *sock, struct sockaddr_in *servAddr, char *community, char* ipArr[], int ifNum)
//{
//	int packetLen, oidLen, recvLen;
//	u_int  addrLen;
//	u_char requestPacket[BUF_MAX] = { '\0', };
//	u_char responsePacket[BUF_MAX] = { '\0', };
//	u_char recvData[BUF_MAX] = { '\0', };
//	u_int reqId = rand();
//
//	addrLen = sizeof(*servAddr);
//	u_int oid[OID_MAX] = { 0, };
//	oidLen = ConvertOID(OID_IP_ADDRESS_ENTRY_ADDR, oid);
//
//	for(int i=0; i<ifNum; i++)
//	{
//		packetLen = MakeSnmpGetNextRequest(requestPacket, community, oid, oidLen, reqId);
//		sendto(*sock, requestPacket, packetLen, 0, (struct sockaddr*)servAddr, sizeof(*servAddr)); 
//		recvLen = recvfrom(*sock, responsePacket, BUF_MAX, 0, (struct sockaddr*)servAddr, &addrLen);
//
//		if(recvLen < 0) {
//			printf("recvfrom() error\n");
//		}
//
//		if(ParseSnmpGetResponse(responsePacket, recvLen, recvData, reqId) < 0) {
//			printf("ParseSnmpGetResponse() Error \n");
//		}
//	
//		int index = 0;
//		int type = recvData[index++];
//		int len = recvData[index++];
//
//		u_char buf[4];
//		for(int i=0; i<4; i++, index++) {
//			buf[i] = recvData[index];
//		}
//
//		if(type == 2)
//		{
//			if(len == 1)
//			{
//				indexArr[i] = recvData[2];
//				oidLen = ConvertOID(OID_INTERFACE_INDEX, oid);
//				oid[oidLen++] = recvData[2];
//				reqId++;
//				continue;
//			}
//		}
//		return -1;
//	}
//	return 0;
//}
