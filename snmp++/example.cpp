#include <libsnmp.h>
#include <snmp_pp/snmp_pp.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

namespace OID
{
	const char* ipRouteNextHop 	= "1.3.6.1.2.1.4.21.1.7";
	const char* ipRouteType 	= "1.3.6.1.2.1.4.21.1.8";
}

using namespace Snmp_pp;
using namespace std;

int SnmpGetNext(const char *ip, const char *community, Vb &vb, vector<string> &buf);
void GetAllNextIp(const char *ip, const char *community, vector<string> &buf);

int main(int argc, char *argv[])
{
	if(argc != 3) {
		cout<<"Usage : "<<argv[0]<<" <IP> <COMMUNITY STRING>\n";
		return 0;
	}

	vector<string> nextIp;
	GetAllNextIp(argv[1], argv[2], nextIp);

	for(auto i : nextIp) {
		cout<<i<<endl;
	}

	return 0;
}

void GetAllNextIp(const char *ip, const char *community, vector<string> &buf)
{
	vector<string> nextHop;
	Vb vbHop(OID::ipRouteNextHop);
	if(SnmpGetNext(ip, community, vbHop, nextHop) < 0) {
		cout<<"SnmpGetNextError"<<endl;
		return;
	}	

	vector<string> type;
	Vb vbType(OID::ipRouteType);
	if(SnmpGetNext(ip, community, vbType, type) < 0) {
		cout<<"SnmpGetNextError"<<endl;
		return;
	}	

	int idx = 0;
	for(auto i : type) {
		if(i == "4") {
			buf.push_back(nextHop[idx]);
		}
		idx++;
	}
}

int SnmpGetNext(const char *ip, const char *community, Vb &vb, vector<string> &buf)
{
	int status;
	string curOid(vb.get_printable_oid());
	
	CTarget ctarget((IpAddress)ip, community, community);
	ctarget.set_version(version2c);
	Pdu pdu;
	
	Snmp snmp(status);
	if(status != SNMP_CLASS_SUCCESS) {
		snmp.error_msg(status);
		return -1;
	}

	pdu += vb;
	if((status = snmp.get_bulk(pdu, ctarget, 0, 20)) == SNMP_CLASS_SUCCESS) {
		for(int i=0; i<pdu.get_vb_count(); i++) {
			pdu.get_vb(vb, i);
			if(curOid[curOid.size()-1] != vb.get_printable_oid()[curOid.size()-1]) {
				break;
			}
			//cout<<vb.get_printable_value()<<endl;
			buf.push_back(vb.get_printable_value());
		}
	}
	else { 
		snmp.error_msg(status);
		return -1;
	}

	return 0;
}

