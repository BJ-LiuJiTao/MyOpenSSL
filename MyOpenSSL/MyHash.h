#pragma once
#include <string>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
using namespace std;

//Ҫ��������
enum MY_HASH_TYPE
{
	H_MD5,
	H_SHA1,
	H_SHA224,
	H_SHA256,
	H_SHA384,
	H_SHA512
};

class MyHash
{
public:
	MyHash(MY_HASH_TYPE type);
	~MyHash();

	//��ʼ��
	bool Init();
	
	//������ݣ����Զ��
	bool Update(string strPutData);

	//����ɢ��ֵ
	bool CalculateHash(string& strOutData);
	
	// ������תʮ������
	void BinToHex(const unsigned char* strBin, string& strHex);
	int m_DigestLen;//ɢ��ֵ����
private:
	
	MY_HASH_TYPE m_Type;//hash����
	MD5_CTX* md5_Ctx;
	SHA_CTX* sha_Ctx;
	SHA256_CTX* sha256_Ctx;
	SHA512_CTX* sha512_Ctx;
};
