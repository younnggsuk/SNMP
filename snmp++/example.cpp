#include <libsnmp.h>
#include <snmp_pp/snmp_pp.h>
#include <string>
#include <vector>
#include <map>
#include <algorithm>

using namespace Snmp_pp;
using namespace std;

#define IP_ADDR_ENTRY_TABLE			"1.3.6.1.2.1.4.20.1.1"
#define IP_NET_TO_MEDIA_NET_ADDR	"1.3.6.1.2.1.4.22.1.3"

int SnmpGetNext(const char *ip, const char *community, Vb &vb, vector<string> &buf);

int main(int argc, char *argv[])
{
	if(argc != 3) {
		cout<<"Usage : "<<argv[0]<<" <IP> <COMMUNITY STRING>\n";
		return 0;
	}

	vector<string> ipAddr;
	Oid oid(IP_ADDR_ENTRY_TABLE);
	Vb vb(oid);
	if(SnmpGetNext(argv[1], argv[2], vb, ipAddr) < 0) {
		cout<<"SnmpGetNextError"<<endl;
		return 0;
	}
	
	map<string, string> l1;
	for(auto i : ipAddr) {
		l1[i] = "";
	}

	Oid oid2(IP_NET_TO_MEDIA_NET_ADDR);
	Vb vb2(oid2);
	for(auto i : ipAddr) {
		vector<string> buf;
		SnmpGetNext(i.c_str(), argv[2], vb2, buf);
		cout<<i<<' ';
		l1[i] = buf.back();
	}
	cout<<endl;

	for(auto i = l1.begin(); i != l1.end(); i++) {
		cout<<(*i).first<<"-->>"<<(*i).second<<endl;
	}

	return 0;
}

int SnmpGetNext(const char *ip, const char *community, Vb &vb, vector<string> &buf)
{
	int status;

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
			if(vb.get_syntax() == 2) {
				break;
			}
			cout<<vb.get_printable_value()<<endl;
			buf.push_back(vb.get_printable_value());
		}
	}
	else { 
		snmp.error_msg(status);
		return -1;
	}

	return 0;
}

