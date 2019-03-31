#include <libsnmp.h>
#include <snmp_pp/snmp_pp.h>
#include <string>


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
//	void SetOid(const char *_oid);
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
//	strcpy(oid, copy.oid);
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
//}
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

int SnmpGetNext(const char *ip, const char *community, Vb &vb, int depth);
void RecursiveGet(const char *ip, const char *community, Vb &curVb, int depth);

int main(int argc, char *argv[])
{
	Vb curVb("1.3.6.1.2.1.4.20.1.1");
	RecursiveGet("127.0.0.1", "public", curVb, 0);
	
	return 0;
}

void RecursiveGet(const char *ip, const char *community, Vb &curVb, int depth)
{
	int status = SnmpGetNext(ip, community, curVb, depth);

	if(status < 0) {
		//cout<<Snmp::error_msg(status)<<endl;
		return;
	}

	Vb hopVb("1.3.6.1.2.1.4.22.1.3");
	RecursiveGet(curVb.get_printable_value(), community, hopVb, depth+1);

	Vb nextVb(curVb.get_printable_oid());
	RecursiveGet(curVb.get_printable_value(), community, nextVb, depth);
}

int SnmpGetNext(const char *ip, const char *community, Vb &vb, int depth)
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
	pdu.get_vb(vb, 0);
	
	for(int i=0; i<depth; i++) {
		cout<<'\t';
	}
	cout<<vb.get_printable_oid()<<endl;

	for(int i=0; i<depth; i++) {
		cout<<'\t';
	}
	cout<<vb.get_printable_value()<<endl;

	return 0;
}

