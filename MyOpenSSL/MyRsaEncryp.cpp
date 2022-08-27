#include "MyRsaEncryp.h"


MyRsaEncryp::MyRsaEncryp() 
{
	m_bIsInit = false;
}

void MyRsaEncryp::BinToHex(const unsigned char* strBin, string& strHex)
{
	//2进制转成16进制 size * 2  + 1是为了\0
	char* szHex = new  char[m_DigestLen * 2 + 1];

	printf("m_DigestLen %d!\n", m_DigestLen);
	for (int i = 0; i < m_DigestLen; i++)
	{
		sprintf(&szHex[i * 2], "%02x", strBin[i]);
	}
	strHex = string(szHex);
}

bool MyRsaEncryp::CreateKeyPair(unsigned long Bignum, int bits, BN_GENCB* cb) 
{ 
	m_rsaCtx = RSA_new();
	if (!m_rsaCtx)
	{
		printf("创建RSA失败!\n");
		return false;
	}

	BIGNUM *a = BN_new();
	if (!a) 
	{
		printf("创建BIGNUM失败!\n");
		return false;
	}

	if (!BN_set_word(a, Bignum)) 
	{
		printf("设置BUGNUM失败!\n");
		return false;
	}

	if (!RSA_generate_key_ex(m_rsaCtx, bits, a, cb)) 
	{
		printf("生成密钥对失败!\n");
		return false;
	}
	m_bIsInit = true;
	return true;
}


bool MyRsaEncryp::Encryp(string strSrc, string& strRes, RSA* rsa)
{
	int	keyLen;
	int len;
	if (!rsa)
	{
		if (!m_bIsInit)
		{
			printf("rsa 未初始化!\n");
			return false;
		}

		RSA* PubKey = RSAPublicKey_dup(m_rsaCtx);
		keyLen =  RSA_size(PubKey);
		unsigned char* to = new unsigned char[keyLen];
		len = RSA_public_encrypt(strSrc.size(), (unsigned char*)strSrc.c_str(), to, PubKey, RSA_PKCS1_PADDING);
		if (len <= 0)
		{
			printf("rsa 加密失败!\n");
			return false;
		}

		strRes = string((char*)to, len);
	}
	else 
	{

		keyLen = RSA_size(rsa);
		unsigned char* to = new unsigned char[keyLen];
		len = RSA_public_encrypt(strSrc.size(), (unsigned char*)strSrc.c_str(), to, rsa, RSA_PKCS1_PADDING);
		if (len <= 0)
		{

			printf("rsa 加密失败!\n");
			return false;
		}

		strRes = string((char*)to, len);
	}
	m_DigestLen = len;
	return true;
}


//私钥解密
bool MyRsaEncryp::Decrypt(string strEncrypVal, string& strEncrypData, RSA* rsa)
{
	int keyLen;
	int len;
	if (!rsa) 
	{
		if (!m_bIsInit) 
		{
			printf("RSA 为初始化!\n");
			return false;
		}
		RSA* PriKey;
		PriKey = RSAPrivateKey_dup(m_rsaCtx);
		if (!PriKey)
		{
			printf("Public key get failed\n");
			return false;
		}
		keyLen = RSA_size(PriKey);

		unsigned char* to = new unsigned char[keyLen];
		
		len = RSA_private_decrypt(strEncrypVal.size(), (const unsigned char*)strEncrypVal.data(), to, PriKey, RSA_PKCS1_PADDING);
		if (len <= 0)
		{
			printf("RSA 解密失败\n");
			return false;
		}
		strEncrypData = string((char*)to, len);
	}
	else
	{
		keyLen = RSA_size(rsa);

		unsigned char* to = new unsigned char[keyLen];
		
		len = RSA_private_decrypt(strEncrypVal.size(), (const unsigned char*)strEncrypVal.c_str(), to, rsa, RSA_PKCS1_PADDING);
		if (len <= 0)
		{
			printf("RSA 解密失败\n");
			return false;
		}
		strEncrypData = string((char*)to, len);
	}
	m_DigestLen = keyLen;
	return true;
}