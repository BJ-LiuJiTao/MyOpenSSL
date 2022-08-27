#pragma once
#include <string>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
using namespace std;

//要创建类型
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

	//初始化
	bool Init();
	
	//添加数据，可以多次
	bool Update(string strPutData);

	//计算散列值
	bool CalculateHash(string& strOutData);
	
	// 二进制转十六进制
	void BinToHex(const unsigned char* strBin, string& strHex);
	int m_DigestLen;//散列值长度
private:
	
	MY_HASH_TYPE m_Type;//hash类型
	MD5_CTX* md5_Ctx;
	SHA_CTX* sha_Ctx;
	SHA256_CTX* sha256_Ctx;
	SHA512_CTX* sha512_Ctx;
};
