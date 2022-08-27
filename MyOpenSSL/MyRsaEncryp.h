#pragma once
#include <openssl/rsa.h>
#include <string>
using namespace std;



class MyRsaEncryp 
{
public:
	MyRsaEncryp();


	//����һ����Կ��
	bool CreateKeyPair(unsigned long Bignum,int bits ,BN_GENCB *cb = nullptr);
	

	//��Կ����
	bool Encryp(string strSrc, string& strRes, RSA* rsa = nullptr);

	//˽Կ����
	bool Decrypt(string strEncrypVal,string& strEncrypData, RSA* rsa = nullptr);

	//˽Կǩ��
	bool PrivateKeySign(string strSrc, );
	
	//��Կ��֤ǩ��


	//��˽Կд���ļ�
	bool WritePrivateKeyToFile();

	//����Կд���ļ�
	bool WritePublicKeyToFile();

	//��ȡ˽Կ�ļ�
	bool RedPrivateKeyOnFile(RSA* rsa);

	//��ȡ��Կ�ļ�
	bool RedPublicKeyOnFile(RSA* rsa);

	//������תʮ������
	void BinToHex(const unsigned char* strBin, string& strHex);
private:
	RSA* m_rsaCtx;
	bool m_bIsInit;
	int m_DigestLen;//
};