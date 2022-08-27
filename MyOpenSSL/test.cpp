

#include "MyHash.h"
#include "MyRsaEncryp.h"
#include <iostream>
#include <windows.h>
//#include "./cuisecAPi.h"

#include <string>
//#include <stdio.h>
#include <objbase.h>

extern "C" { FILE __iob_func[3] = { *stdin,*stdout,*stderr }; }


void HashTest();//哈希
void RsaTest();//非对称加解密and签名验签名

int main() 
{

	//Sleep(1000);
	RsaTest();
	string str;
	system("pause");
	return 0;
}

void HashTest() 
{
	printf(">>>>>>>>>>>>>>>>>>HashTest start>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
	string strSrc = "hello, world";
	string strHashVal;
	printf("src : %s\n", strSrc.c_str());
	MyHash test(H_SHA1);

	if (!test.Init())
	{
		printf("初始化失败!\n");
		return ;
	}

	if (!test.Update(strSrc))
	{
		printf("添加数据失败!\n");
		return ;
	}
	if (!test.CalculateHash(strHashVal))
	{
		printf("Hash 失败!\n");
		return ;
	}
	string strHexHashVal;
	char* str = new char(test.m_DigestLen * 2 + 1);
	int len = 0;

	test.BinToHex((unsigned char*)strHashVal.c_str(), strHexHashVal);
	cout << "Hash : " << strHexHashVal.c_str() << endl;

	printf(">>>>>>>>>>>>>>>>>>HashTest end>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
}

void RsaTest() 
{
	printf(">>>>>>>>>>>>>>>>>>RsaTest start>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
	string strSrc = "hello, world";
	string strEncrypVal;
	string strHex;
	string strDecrypVal;
	MyRsaEncryp test;

	
#ifdef 1
	//创建密钥对使用创建的密钥对进行加解密//
	//密钥长度
	test.CreateKeyPair(12345, 1024);
	test.Encryp(strSrc, strEncrypVal);
	test.BinToHex((const unsigned char*)strEncrypVal.c_str(), strHex);

	cout << "rsa  encrypt data: " << strHex << endl;
	test.Decrypt(strEncrypVal, strDecrypVal);
	cout << "rsa decrypt data data: " << strDecrypVal << endl;
	//创建密钥对使用创建的密钥对进行加解密//
#endif // 1
	//创建密钥对然后保存到本地，然后读取pem文件其中私钥解密公钥加密
	 


	//创建密钥对然后保存到本地，然后读取pem文件其中私钥解密公钥加密
	printf(">>>>>>>>>>>>>>>>>>RsaTest end>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
}