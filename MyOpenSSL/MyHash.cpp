#include "MyHash.h"
#include <iostream>

MyHash::MyHash(MY_HASH_TYPE type) 
{
	m_Type = type;
	switch (type)
	{
	case H_MD5: 
		{
			md5_Ctx = new MD5_CTX;
			break;
		}
	case H_SHA1:
		{
			sha_Ctx = new SHA_CTX;
			break;
		}
	case H_SHA224:
	case H_SHA256:
		{
			sha256_Ctx = new SHA256_CTX;
			break;
		}
	case H_SHA384:
	case H_SHA512:
		{
			sha512_Ctx = new SHA512_CTX;
			break;
		}
	
	default:
		{
			printf("Type err!\n");
			return;
		}
	}

	printf("<<<<<<<<<<<<<<创建MyHash成功!!!>>>>>>>>>>>>>>\n");
}

MyHash::~MyHash() 
{
	switch (m_Type)
	{
	case H_MD5:
		{
			delete md5_Ctx;
			break;
		}
	case H_SHA1:
		{
			delete sha_Ctx ;
			break;
		}
	case H_SHA224:
	case H_SHA256:
		{
			delete sha256_Ctx;
			break;
		}
	case H_SHA384:
	case H_SHA512:
		{
			delete sha512_Ctx;
			break;
		}
	}
	printf("<<<<<<<<<<<<<<释放MyHash成功!!!>>>>>>>>>>>>>>\n");
	
}


//初始化
bool MyHash::Init()
{
	switch (m_Type)
	{
	case H_MD5:
	{
		if (!MD5_Init(md5_Ctx))
		{
			return false;
		}
		m_DigestLen = MD5_DIGEST_LENGTH;
		break;
	}
	case H_SHA1:
	{
		if (!SHA1_Init(sha_Ctx))
		{
			return false;
		}
		m_DigestLen = SHA_DIGEST_LENGTH;
		break;
	}
	case H_SHA224:
	{
		if (!SHA224_Init(sha256_Ctx))
		{
			return false;
		}
		m_DigestLen = SHA224_DIGEST_LENGTH;
		break;
	}
	case H_SHA256:
	{
		if (!SHA256_Init(sha256_Ctx))
		{
			return false;
		}
		m_DigestLen = SHA256_DIGEST_LENGTH;
		break;
	}
	case H_SHA384:
	{
		if (!SHA384_Init(sha512_Ctx))
		{
			return false;
		}
		m_DigestLen = SHA384_DIGEST_LENGTH;
		break;
	}
	case H_SHA512:
	{
		if (!SHA512_Init(sha512_Ctx))
		{
			return false;
		}
		m_DigestLen = SHA512_DIGEST_LENGTH;
		break;
	}
	default:
	{
		printf("初始化err!\n");
	}
	}
	printf("<<<<<<<<<<<<<<初始化成功!!!>>>>>>>>>>>>>>\n");
	return true;
}

//添加数据，可以多次
bool MyHash::Update(string strPutData)
{
	size_t len = strPutData.length();
	
	switch (m_Type)
	{
	case H_MD5:
	{
		if (!MD5_Update(md5_Ctx, strPutData.data(), len))
		{
			return false;
		}
		break;
	}
	case H_SHA1:
	{
		if (!SHA1_Update(sha_Ctx, strPutData.data(), len))
		{
			return false;
		}
		break;
	}
	case H_SHA224:
	{
		if (!SHA224_Update(sha256_Ctx, strPutData.data(), len))
		{
			return false;
		}
		break;
	}
	case H_SHA256:
	{
		if (!SHA256_Update(sha256_Ctx, strPutData.data(), len))
		{
			return false;
		}
		break;
	}
	case H_SHA384:
	{
		if (!SHA384_Update(sha512_Ctx, strPutData.data(), len))
		{
			return false;
		}
		break;
	}
	case H_SHA512:
	{
		if (!SHA512_Update(sha512_Ctx, strPutData.data(), len))
		{
			return false;
		}
		break;
	}
	}

	printf("<<<<<<<<<<<<<<添加数据成功!!!>>>>>>>>>>>>>>\n");
	return true;
}

//计算散列值
bool MyHash::CalculateHash(string& strOutData)
{
	unsigned char* md =nullptr;

	switch (m_Type)
	{
	case H_MD5:
	{
		md = new unsigned char[MD5_DIGEST_LENGTH];
		if(!MD5_Final(md, md5_Ctx))
		{
			delete []md;
			return false;
		}
		break;
	}
	case H_SHA1:
	{
		md = new unsigned char[SHA_DIGEST_LENGTH];
		if(!SHA1_Final(md, sha_Ctx))
		{
			delete[]md;
			return false;
		}
		break;
	}
	case H_SHA224:
	{
		md = new unsigned char[SHA224_DIGEST_LENGTH];
		if(!SHA224_Final(md, sha256_Ctx))
		{
			delete[]md;
			return false;
		}
		break;
	}
	case H_SHA256:
	{
		md = new unsigned char[SHA256_DIGEST_LENGTH];
		if(!SHA256_Final(md, sha256_Ctx))
		{
			delete[]md;
			return false;
		}
		break;
	}
	case H_SHA384:
	{
		md = new unsigned char[SHA384_DIGEST_LENGTH];
		if(!SHA384_Final(md, sha512_Ctx))
		{
			delete[]md;
			return false;
		}
		break;
	}
	case H_SHA512:
	{
		md = new unsigned char[SHA512_DIGEST_LENGTH];
		if (!SHA512_Final(md ,sha512_Ctx))
		{
			delete[]md;
			return false;
		}
		break;
	}
	}

	printf("<<<<<<<<<<<<<<HASH计算成功!!!>>>>>>>>>>>>>>\n");
	
	strOutData = string((char *)md);


	printf("md : %s\n", md);
	printf("strOutData : %s\n", strOutData.c_str());
	delete[]md;
	return true;
}

// 二进制转十六进制
void MyHash::BinToHex(const unsigned char* strBin, string& strHex)
{
	//2进制转成16进制 size * 2  + 1是为了\0
	char* szHex = new  char[m_DigestLen * 2 + 1];

	printf("m_DigestLen %d!\n", SHA_DIGEST_LENGTH);
	for (int i = 0; i < m_DigestLen; i++)
	{
		sprintf(&szHex[i * 2], "%02x", strBin[i]);
	}
	strHex = string(szHex);
}