#include <libsnmp.h>
#include <snmp_pp/snmp_pp.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

namespace OID
{
	const char* ipForwarding 	= "1.3.6.1.2.1.4.1";
	const char* ipRouteNextHop 	= "1.3.6.1.2.1.4.21.1.7";
	const char* ipRouteType 	= "1.3.6.1.2.1.4.21.1.8";
}

using namespace Snmp_pp;
using namespace std;

int SnmpBulk(const char *ip, const char *community, Vb &vb, vector<string> &buf);
int SnmpNext(const char *ip, const char *community, Vb &vb, vector<string> &buf);

void GetAllNextIp(const char *ip, const char *community, vector<string> &buf);
void RecursiveGetAllNextIp(const char *ip, const char *community, 
							vector<pair<int, string>> &buf, int depth); 

int main(int argc, char *argv[])
{
	if(argc != 3) {
		cout<<"Usage : "<<argv[0]<<" <IP> <COMMUNITY STRING>\n";
		return 0;
	}

	vector<pair<int, string>> allIp;
	RecursiveGetAllNextIp(argv[1], argv[2], allIp, 0);

	cout<<"-------------------------------------------------"<<endl;
	for(auto i : allIp) {
		for(int count=0; count<i.first; count++) {
			cout<<'\t';
		}
		cout<<i.second<<endl;
	}
	cout<<"-------------------------------------------------"<<endl;

//	vector<string> nextIp;
//	GetAllNextIp(argv[1], argv[2], nextIp);
//
//	vector<string> nextIp2;
//	for(auto i : nextIp) {
//		GetAllNextIp(i.c_str(), argv[2], nextIp2);
//	}
//
//	for(auto i : nextIp) {
//		cout<<i<<endl;
//	}

	return 0;
}

void RecursiveGetAllNextIp(const char *ip, const char *community, vector<pair<int, string>> &buf, int depth) 
{
	vector<string> nextIp;
	GetAllNextIp(ip, community, nextIp);
	if(nextIp.empty()) {
		return;
	}
	
	for(auto i : nextIp) {
		buf.push_back(make_pair(depth, i));
	}
	
	for(auto i : nextIp) {
		RecursiveGetAllNextIp(i.c_str(), community, buf, depth+1);
	}
}

void GetAllNextIp(const char *ip, const char *community, vector<string> &buf)
{
	vector<string> nextHop;
	Vb vbHop(OID::ipRouteNextHop);
	if(SnmpBulk(ip, community, vbHop, nextHop) < 0) {
		return;
	}

	vector<string> type;
	Vb vbType(OID::ipRouteType);
	if(SnmpBulk(ip, community, vbType, type) < 0) {
		return;
	}

	vector<string> forwarding;
	Vb vbForwarding(OID::ipForwarding);
	for(auto i : nextHop) {
		vector<string> buf;
		Vb vbForwarding(OID::ipForwarding);
		if(SnmpNext(i.c_str(), community, vbForwarding, buf) < 0) {
			forwarding.push_back("0");
			continue;
		}
		forwarding.push_back(buf[0]);
	}

	for(vector<string>::size_type i=0; i<type.size(); i++) {
		if( (type[i] == "4") && (forwarding[i] == "1") ) {
			buf.push_back(nextHop[i]);
		}
	}
}

int SnmpNext(const char *ip, const char *community, Vb &vb, vector<string> &buf)
{
	int status;

	CTarget ctarget((IpAddress)ip, community, community);
	ctarget.set_version(version2c);
	Pdu pdu;
	
	Snmp snmp(status);
	if(status != SNMP_CLASS_SUCCESS) {
		cout<<snmp.error_msg(status)<<endl;
		return -1;
	}

	pdu += vb;
	if((status = snmp.get_next(pdu, ctarget)) == SNMP_CLASS_SUCCESS) {
		pdu.get_vb(vb, 0);
		//cout<<vb.get_printable_oid()<<' '<<vb.get_printable_value()<<endl;
		buf.push_back(vb.get_printable_value());
	}
	else { 
		cout<<snmp.error_msg(status)<<endl;
		return -1;
	}

	return 0;
}


int SnmpBulk(const char *ip, const char *community, Vb &vb, vector<string> &buf)
{
	int status;
	string curOid(vb.get_printable_oid());
	
	CTarget ctarget((IpAddress)ip, community, community);
	ctarget.set_version(version2c);
	Pdu pdu;
	
	Snmp snmp(status);
	if(status != SNMP_CLASS_SUCCESS) {
		cout<<snmp.error_msg(status)<<endl;
		return -1;
	}

	pdu += vb;
	if((status = snmp.get_bulk(pdu, ctarget, 0, 20)) == SNMP_CLASS_SUCCESS) {
		for(int i=0; i<pdu.get_vb_count(); i++) {
			pdu.get_vb(vb, i);
			if(curOid[curOid.size()-1] != vb.get_printable_oid()[curOid.size()-1]) {
				break;
			}
			//cout<<vb.get_printable_oid()<<' '<<vb.get_printable_value()<<endl;
			buf.push_back(vb.get_printable_value());
		}
	}
	else { 
		cout<<snmp.error_msg(status)<<endl;
		return -1;
	}

	return 0;
}

