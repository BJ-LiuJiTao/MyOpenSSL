

#include "MyHash.h"
#include "MyRsaEncryp.h"
#include <iostream>
#include <windows.h>
//#include "./cuisecAPi.h"

#include <string>
//#include <stdio.h>
#include <objbase.h>

extern "C" { FILE __iob_func[3] = { *stdin,*stdout,*stderr }; }


void HashTest();//��ϣ
void RsaTest();//�ǶԳƼӽ���andǩ����ǩ��

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
		printf("��ʼ��ʧ��!\n");
		return ;
	}

	if (!test.Update(strSrc))
	{
		printf("�������ʧ��!\n");
		return ;
	}
	if (!test.CalculateHash(strHashVal))
	{
		printf("Hash ʧ��!\n");
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
	//������Կ��ʹ�ô�������Կ�Խ��мӽ���//
	//��Կ����
	test.CreateKeyPair(12345, 1024);
	test.Encryp(strSrc, strEncrypVal);
	test.BinToHex((const unsigned char*)strEncrypVal.c_str(), strHex);

	cout << "rsa  encrypt data: " << strHex << endl;
	test.Decrypt(strEncrypVal, strDecrypVal);
	cout << "rsa decrypt data data: " << strDecrypVal << endl;
	//������Կ��ʹ�ô�������Կ�Խ��мӽ���//
#endif // 1
	//������Կ��Ȼ�󱣴浽���أ�Ȼ���ȡpem�ļ�����˽Կ���ܹ�Կ����
	 


	//������Կ��Ȼ�󱣴浽���أ�Ȼ���ȡpem�ļ�����˽Կ���ܹ�Կ����
	printf(">>>>>>>>>>>>>>>>>>RsaTest end>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
}