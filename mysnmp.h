#ifndef __MY_SNMP_H__
#define __MY_SNMP_H__

#define PORT_SNMP 161 
#define BUF_MAX 1000
#define OID_MAX 128

// interface

#define OID_INTERFACE_NUM		    "1.3.6.1.2.1.2.1.0"
#define OID_INTERFACE_INDEX		    "1.3.6.1.2.1.2.2.1.1"
#define OID_INTERFACE_DESC 			"1.3.6.1.2.1.2.2.1.2"
#define OID_INTERFACE_MTU 			"1.3.6.1.2.1.2.2.1.4"
#define OID_INTERFACE_BANDWIDTH		"1.3.6.1.2.1.2.2.1.5"
#define OID_INTERFACE_MAC_ADDR 		"1.3.6.1.2.1.2.2.1.6"
#define OID_INTERFACE_LINK_STATUS	"1.3.6.1.2.1.2.2.1.8"
#define OID_INTERFACE_IN_OCTETS 	"1.3.6.1.2.1.2.2.1.10"
#define OID_INTERFACE_OUT_OCTETS 	"1.3.6.1.2.1.2.2.1.16"

//// ip
//
//#define OID_IP_ADDRESS_ENTRY_ADDR	"1.3.6.1.2.1.4.20.1.1"
//#define OID_IP_ADDRESS_ENTRY_INDEX	"1.3.6.1.2.1.4.20.1.2"

/*
 	Socket
 */
void MakeUDPSocket(int *sock, struct sockaddr_in *servAddr, char *ipAddr);

/*
 	SNMP Get-request
 */
int MakeSnmpGetRequest(u_char requestPacket[], char *community, u_int oid[], int oidLen, u_int reqId);

int ConvertOID(char *oidStr, u_int oid[]);

/*
 	SNMP Get-next-request
 */
int MakeSnmpGetNextRequest(u_char requestPacket[], char *community, u_int oid[], int oidLen, u_int reqId);

/* 
    SNMP Get-response
 */
int ParseSnmpGetResponse(u_char responsePacket[], int recvLen, u_char recvData[], u_int reqId);

int ParseAsnHeader(u_char responsePacket[], int *index);
int ParsePduLength(u_char responsePacket[], int recvLen, int *index);
int ParseVersion(u_char responsePacket[], int *index);
int ParseCommunity(u_char responsePacket[], int *index);
int ParseResponse(u_char responsePacket[], int recvLen, int *index);
int ParseRequestId(u_char responsePacket[], int *index, u_int reqId);
int ParseErrorStatus(u_char responsePacket[], int *index);
int ParseErrorIndex(u_char responsePacket[], int *index);
int ParseVarBindingSequence(u_char responsePacket[], int *index);
int ParseOID(u_char responsePacket[], int *index);

/*
	Get Interface Num
 */
int GetInterfaceNum(int *sock, struct sockaddr_in *servAddr, char *community);

/*
	Get All Interface Index
 */
int GetAllInterfaceIndex(int *sock, struct sockaddr_in *servAddr, char *community, int *indexArr, int ifNum);

/*
	Get Interface Descriptor
 */
void GetInterfaceDesc(int *sock, struct sockaddr_in *servAddr, char *community, int ifIndex);

/*
	Get Interface MTU
 */
void GetInterfaceMTU(int *sock, struct sockaddr_in *servAddr, char *community, int ifIndex);

/*
	Get Interface Bandwidth
 */
void GetInterfaceBandwidth(int *sock, struct sockaddr_in *servAddr, char *community, int ifIndex);

/*
	Get Interface LinkStatus
 */
void GetInterfaceLinkStatus(int *sock, struct sockaddr_in *servAddr, char *community, int ifIndex, int *state);

/*
	Get Interface InOctets
 */
void GetInterfaceInOctet(int *sock, struct sockaddr_in *servAddr, char *community, int ifIndex);

/*
	Get Interface OutOctets
 */
void GetInterfaceOutOctet(int *sock, struct sockaddr_in *servAddr, char *community, int ifIndex);

/*
	Get Interface MAC-Address
 */
void GetInterfaceMacAddr(int *sock, struct sockaddr_in *servAddr, char *community, int ifIndex);

#endif
