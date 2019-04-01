#include <libsnmp.h>
#include <snmp_pp/snmp_pp.h>
#include <string>
#include <vector>
#include <algorithm>

using namespace Snmp_pp;
using namespace std;

///////////////////////////////////////////////////////////
//class SnmpResult
//{
//private:
//	char *oid;
//	char *value;
//public:	
//	SnmpResult();
//	SnmpResult(const char *_oid, const char *_value);
//	SnmpResult(const SnmpResult &copy);
//	void SetOid(ceonst char *_oid);
//	void SetValue(const char *_value);
//	const char* GetOid() const;
//	const char* GetValue() const;
//	void PrintOid() const;
//	void PrintValue() const;
//	~SnmpResult();
//};
//
//SnmpResult::SnmpResult() : oid(NULL), value(NULL)
//{ } 
//SnmpResult::SnmpResult(const char *_oid, const char *_value)
//{
//	oid = new char[strlen(_oid)+1];
//	value = new char[strlen(_value)+1];
//	strcpy(oid, _oid);
//	strcpy(value, _value);
//}
//SnmpResult::SnmpResult(const SnmpResult &copy)
//{
//	oid = new char[strlen(copy.oid)+1];
//	value = new char[strlen(copy.value)+1];
//	strcpy(oid, copy.oid);e
//	strcpy(value, copy.value);
//}
//void SnmpResult::SetOid(const char *_oid)
//{
//	if(oid != NULL) {
//		delete []oid;
//	}
//	oid = new char[strlen(_oid)+1];
//	strcpy(oid, _oid);
//}
//void SnmpResult::SetValue(const char *_value)
//{
//	if(value != NULL) {
//		delete []value;
//	}
//	value = new char[strlen(_value)+1];
//	strcpy(value, _value);
//}
//const char* SnmpResult::GetOid() const
//{
//	return oid;
//}e
//const char* SnmpResult::GetValue() const
//{
//	return value;
//}
//void SnmpResult::PrintOid() const
//{
//	cout<<oid<<endl;
//}
//void SnmpResult::PrintValue() const
//{
//	cout<<value<<endl;
//}
//SnmpResult::~SnmpResult()
//{
//	if(oid != NULL) {
//		delete []oid;
//	}
//	if(value != NULL) {
//		delete []value;
//	}
//}
///////////////////////////////////////////////

#define IP_ADDR_ENTRY_TABLE			"1.3.6.1.2.1.4.20.1.1"
#define IP_NET_TO_MEDIA_NET_ADDR	"1.3.6.1.2.1.4.22.1.3"

int SnmpGetNext(const char *ip, const char *community, Vb &vb, int oidIdx);
void RecursiveGet(const char *ip, const char *community, Vb &curVb, int oidIdx);

int main(int argc, char *argv[])
{
	Oid oid(IP_ADDR_ENTRY_TABLE);
	Vb curVb(oid);
	RecursiveGet("127.0.0.1", "public", curVb, oid.len());
	


	return 0;
}

void RecursiveGet(const char *ip, const char *community, Vb &curVb, int oidIdx)
{
	int status = SnmpGetNext(ip, community, curVb, oidIdx);
	
	if(status < 0) {
		cout<<Snmp::error_msg(status)<<endl;
		return;
	}

	Vb nextVb(curVb.get_printable_oid());
	RecursiveGet(curVb.get_printable_value(), community, nextVb, oidIdx);
}

int SnmpGetNext(const char *ip, const char *community, Vb &vb, int oidIdx)
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

	auto cur = vb.get_printable_oid()[oidIdx+1];
	pdu.get_vb(vb, 0);
	auto next = vb.get_printable_oid()[oidIdx+1];

	cout<<"cur : "<<cur<<", "<<next<<endl;

	cout<<vb.get_printable_oid()<<endl;
	cout<<vb.get_printable_value()<<endl;

	return 0;
}

