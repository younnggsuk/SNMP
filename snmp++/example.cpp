#include <libsnmp.h>
#include <snmp_pp/snmp_pp.h>
#include <string>
#include <vector>
#include <algorithm>

using namespace Snmp_pp;
using namespace std;

#define IP_ADDR_ENTRY_TABLE			"1.3.6.1.2.1.4.20.1.1"
#define IP_NET_TO_MEDIA_NET_ADDR	"1.3.6.1.2.1.4.22.1.3"

int SnmpGetNext(const char *ip, const char *community, Vb &vb, int len, vector<string> &arr);

int main(int argc, char *argv[])
{
	if(argc != 3) {
		cout<<"Usage : "<<argv[0]<<" <IP> <COMMUNITY STRING>\n";
		return 0;
	}

	vector<string> arr;

	int status;
	Vb curVb(IP_ADDR_ENTRY_TABLE);
	if((status = SnmpGetNext("127.0.0.1", argv[2], curVb, strlen(curVb.get_printable_oid()), arr)) < 0) {
		Snmp::error_msg(status);
	}

	cout<<endl<<endl;

	Vb nextVb(IP_NET_TO_MEDIA_NET_ADDR);
	int ipNum = arr.size();
	for(int i=0; i<ipNum; i++) {
		if((status = SnmpGetNext(arr[i].c_str(), argv[2], nextVb, strlen(nextVb.get_printable_oid()), arr)) < 0) {
			Snmp::error_msg(status);
		}
	}

	for(auto i : arr) {

		cout<<i<<endl;
	}

	return 0;
}

int SnmpGetNext(const char *ip, const char *community, Vb &vb, int len, vector<string> &arr)
{
	int status;

	CTarget ctarget((IpAddress)ip, community, community);
	ctarget.set_version(version2c);
	Pdu pdu;
	
	Snmp snmp(status);
	if(status != SNMP_CLASS_SUCCESS) {
		return status;
	}

	pdu += vb;
	if((status = snmp.get_next(pdu, ctarget)) != SNMP_CLASS_SUCCESS){
		return status;
	}

	int prevOidEnd = vb.get_printable_oid()[len-1];
	pdu.get_vb(vb, 0);
	if(prevOidEnd != vb.get_printable_oid()[len-1]) {
		return 0;
	}

	arr.push_back(vb.get_printable_value());

	Vb nextVb(vb.get_printable_oid());
	SnmpGetNext(vb.get_printable_value(), community, nextVb, len, arr);

	return 0;
}

