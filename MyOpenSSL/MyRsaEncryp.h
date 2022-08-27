#pragma once
#include <openssl/rsa.h>
#include <string>
using namespace std;



class MyRsaEncryp 
{
public:
	MyRsaEncryp();


	//创建一个密钥对
	bool CreateKeyPair(unsigned long Bignum,int bits ,BN_GENCB *cb = nullptr);
	

	//公钥加密
	bool Encryp(string strSrc, string& strRes, RSA* rsa = nullptr);

	//私钥解密
	bool Decrypt(string strEncrypVal,string& strEncrypData, RSA* rsa = nullptr);

	//私钥签名
	bool PrivateKeySign(string strSrc, );
	
	//公钥验证签名


	//将私钥写入文件
	bool WritePrivateKeyToFile();

	//将公钥写入文件
	bool WritePublicKeyToFile();

	//读取私钥文件
	bool RedPrivateKeyOnFile(RSA* rsa);

	//读取公钥文件
	bool RedPublicKeyOnFile(RSA* rsa);

	//二进制转十六进制
	void BinToHex(const unsigned char* strBin, string& strHex);
private:
	RSA* m_rsaCtx;
	bool m_bIsInit;
	int m_DigestLen;//
};