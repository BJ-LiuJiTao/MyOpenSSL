视频：https://www.bilibili.com/video/BV1xT4y1v7nm?p=17&vd_source=af2138015985cf9930c2be18847871be 

OPENSSL_GITHUB_SRC：https://github.com/openssl/openssl

OPENSSL_LIB:https://slproweb.com/products/Win32OpenSSL.html

# 一、哈希

## 1、特点：

- 不可逆
- 抗碰撞性强
  - 不通的数据拥有不同的哈希值，相同的数据哈希值是相同的
- 原始数据有细微变化，哈希值的变化非常大
- 通过哈希函数将原始数据进行运算，得到的哈希长度是固定的
- 原始的哈希值是一个定长的`二进制`字符串字符串

## 2、哈希算法：

### （1）sha1 介绍

碰撞性被突破了

- md5
  - 散列值：16byte
- sha1
  - 散列值：20byte

### （2）sha2 介绍

- sha224
  - 散列值：28byte
- sha256
  - 散列值：32byte
- sha384
  - 散列值：48byte
- sha512
  - 散列值：64byte

`以上说的散列值长度是数据长度，一般散列值使用16进制格式字符串表示的，看到的字符长度是原来的二倍长`

### （3）使用的头文件

```
#include<openssl/md5.h>
#include<openssl/sha.h>
```

### （4）md5

```c++
# define MD5_DIGEST_LENGTH 16 //md5散列值的长度

//初始化函数，初始化参数C
int MD5_Init(MD5_CTX *c);
//C 传入参数

//添加md5运算的数据 ->没有计算
//该函数可以进行多次数据添加 ->多次调用
int MD5_Update(MD5_CTX *c, const void *data, size_t len);
/*
	参数:
		-c: MD5_Init初始化得到的
		-data:传入参数，字符串
		-len：data的长度
*/

// 对添加的数据进行md5的计算
int MD5_Final(unsigned char *md, MD5_CTX *c);
/*
	参数:
		-md:传出参数，存储得到的哈希值
		-c：MD5_Init初始化得到的
*/

//通过传递的参数，直接生成一个md5哈希值
unsigned char *MD5(const unsigned char *d, size_t n, unsigned char *md);
/*
	参数：
		-d:传入，要进行md5的运算的字符串
		-n:传入，字符串的长度
		-md：传出，存储md5的哈希值
	返回值：指向md的地址
*/

void MD5_Transform(MD5_CTX *c, const unsigned char *b);
```

### （5）sha1

```c++
# define SHA_DIGEST_LENGTH 20 //sha1的散列值长度

//参考md5

int SHA1_Init(SHA_CTX *c);
int SHA1_Update(SHA_CTX *c, const void *data, size_t len);
int SHA1_Final(unsigned char *md, SHA_CTX *c);
unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);
void SHA1_Transform(SHA_CTX *c, const unsigned char *data);
```

### （6）sha224

```c++
# define SHA224_DIGEST_LENGTH    28

int SHA224_Init(SHA256_CTX *c);
int SHA224_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA224_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA224(const unsigned char *d, size_t n, unsigned char *md);
```

### （7）sha256

```c++
# define SHA256_DIGEST_LENGTH    32
//参考md5
int SHA256_Init(SHA256_CTX *c);
int SHA256_Update(SHA256_CTX *c, const void *data, size_t len);
int SHA256_Final(unsigned char *md, SHA256_CTX *c);
unsigned char *SHA256(const unsigned char *d, size_t n, unsigned char *md);
void SHA256_Transform(SHA256_CTX *c, const unsigned char *data);

```

### （8）sha384

```c++
# define SHA384_DIGEST_LENGTH    48
//参考md5
int SHA384_Init(SHA512_CTX *c);
int SHA384_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA384_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA384(const unsigned char *d, size_t n, unsigned char *md);
```

### （9）sha512

```c++
# define SHA512_DIGEST_LENGTH    64
//参考md5
int SHA512_Init(SHA512_CTX *c);
int SHA512_Update(SHA512_CTX *c, const void *data, size_t len);
int SHA512_Final(unsigned char *md, SHA512_CTX *c);
unsigned char *SHA512(const unsigned char *d, size_t n, unsigned char *md);
void SHA512_Transform(SHA512_CTX *c, const unsigned char *data);
```

# 二、非对称加密

`RSA算法密钥越长越好，安全性越好，加密解密所需时间越长,密钥长度增长一倍，公钥操作所需时间增加约4倍，私钥操作所需时间约8被，公私钥生成时间约增长16倍`

## 1、特点

- 秘钥是一个密钥对：公钥，私钥
  - 公钥加密，必须私钥解密，
  - 私钥加密，必须公钥解密
- 加密强度比较高，效率低
  - 不会使用非对称加密，加密强度特别大的数据
- 应用场景
  - 秘钥分法->对称加密
    - 核心思想：加密的时候,公钥加密，私钥解密
    - 分法步骤：
      - 假设A,B两端
      - A端生成了一个密钥对，分法公钥，B端有了公钥
      - B端生成一个对称加密的密钥，使用公钥加密->密文
      - B端将密文发送给A
      - A端接收数据->密文，使用私钥对密文解密->对称加密的秘钥
  - 签名->验证是否被篡改，验证数据的所有者
    - 核心思想`私钥加密，公钥解密`
    - A,B两端，假设A要发送数据
      - A端生成一个密钥对，将公钥进行分法B端，自己留私钥
    - 签名
      - A对原始数据进行哈希运算->哈希值
      - A使用私钥对哈希值加密->密文
      - 将原始数据+密文发送给B
    - 效验签名
      - B接收数据：密文+收到的原始数据
      - 使用公钥对密文进行解密->哈希值old（得到`信息摘要`）
      - 使用hax算法对接收到`原始数据`进行哈希运算->new
      - 比较两个哈希值
        - 相同:校验成功
        - 不同：失败

## 2、生成RSA密钥对

```c++
#include<openssl/rsa.h>
//申请一块内存，存储了公钥和私钥

//如果想得到RSA类型变量必须使用 RSA_new（）；
RSA *RSA_new(void);

//为了得到BIGNUM
BIGNUM *BN_new(void);
BIO *BIO_new(const BIO_METHOD *type);
int BN_set_word(BIGNUM *a, BN_ULONG w);

//生成密钥对，密钥存储在内存中
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *e, BN_GENCB *cb);
/*
	参数:
		-rsa:通过RSA_new();
        -bits:密钥的长度，单位是bit，常用的长度1024*n(n正整数)
        -e:比较大的数（5位以内），
        	-通过BN_nwe的到的变量
        	-初始化：BN_set_word(e, 12345)
		-cb：回调函数，一般用不到 为空        
*/


//创建BIO对象
//密钥写入磁盘文件的时候，需要编码->base64

//打开文件创建一个bio对象
BIO *BIO_new_file(const char *filename, const char *mode);
/*
	参数:
		-filename:文件名
		-mode：文件打开方式和fopen的打开方式一样
*/

//将RSA的私钥数据写入到BIO打开的文件里面
int PEM_write_bio_RSAPrivateKey(BIO* bp, CONST RSA* x, const EVP_CIPHER* enc, unsigned char* kstr, int klen,  pem_password_cd *cb, void *u);
/*
	参数：
		-bp:BIO_nwe_file()
		-x:之前的到的RSA密钥
		其他参照PEM_write_RSAPrivateKey
*/
//RSA的公钥数据写入到BIO打开文件里面
int PEM_write_bio_RSAPublicKey(BIO* bp, CONST RSA* x);
/*
	参数：
	-bp:BIO_nwe_file()
	-x:之前得到RSA密钥对
*/
//读取密钥
RSA* PEM_read_bio_RSAPrivateKey(BIO* bp, RSA** r, pem_password_cb *cb, void* u);
RSA* PEM_read_bio_RSAPrivateKey(BIO* bp, RSA** r, pem_password_cb *cb, void* u);
/*
	参数：
	-bp：通过BIO_new_file();函数得到该指针
	-r:传递一个RSA* rsa指针的地址 传出参数->公钥/私钥
	-cb：回调参数
	-u：回调传参
*/



//将参数从rsa中提取公钥
//RSA的公私钥类型是一样的
RSA* RSAPublicKey_dup(RSA* rsa);
/*
	-rsa参数：秘钥信息
	返回值公钥
*/
//将参数从rsa中提取私钥
RSA* RSAPrivateKey_dup(RSA* rsa);
/*
	-rsa参数：秘钥信息
	返回值私钥
*/

//释放BIO资源
int BIO_free(BIO *a);




//////////////////////////////////////////////////////////////////////////////////////
//写入文件中的私钥数据不是原始数据，写入的是编码之后的数据
//写入的是一种PEM的文件格式，数据使用base64编码
int PEM_write_RSAPublicKey(FILE* fp, const RSA* r);
int PEM_write_RSAPrivateKey(FILE* fp, const RSA*r, const EVP_CIPHER* enc, unsigned char* kstr, int klen,  pem_password_cd *cb, void *u);
/*
	参数：
		-fp:需要打开一个磁盘文件，并且指定写权限
		-r：存储了密钥对
		////私钥独有的参数
		-enc:指定的加密算法->对称加密 NULL
		-kstr:对称加密的密钥 NULL
		-klen:密钥长度 0
		-cb:回调长度 NULL
		-u:给回调的传参 NULL
*/

int PEM_read_RSAPublicKey(FILE* fp, RSA** r, pem_password_cb *cb, void* u);
int PEM_read_RSAPrivateKey(FILE* fp, RSA** r, pem_password_cb *cb, void* u);
```

## 3、加密

> 以块的方式进行加密的，加密的数据长度,不能大于密钥长度
>
> - 假设：秘钥长度：1024bit = 128byte



```c++
//公钥加密
int RSA_public_encrypt(int flen, const unsigned char *from,
                       unsigned char *to, RSA *rsa, int padding);

//私钥解密
int RSA_private_decrypt(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
//////////////签名使用///////////////////
//私钥加密
int RSA_private_encrypt(int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
//公钥解密
int RSA_public_decrypt(int flen, const unsigned char *from,
                       unsigned char *to, RSA *rsa, int padding);
/*
参数：
    - flen :要加密/解密的数据长度
        长度 0 < flen <= 密钥长度 -11
    - from: 要加密/解密的数据
    - to：存储，存储数据，加密->密文，解密->存储明文
    - rsa:秘钥：公钥或者私钥
	- padding:数据填充,不需要使用者做
    	-RSA_PKCS1_PADDING //公共密钥填充方案 填充11个字节

*/
```



## 4、签名



```
//签名
int RSA_sign(int type, const unsigned char *m, unsigned int m_length,
             unsigned char *sigret, unsigned int *siglen, RSA *rsa);
/*
	参数：
		-type:使用的哈希算法
			-NID_MD5
			-NID_SHA1
		-m:要进行签名的数据
		-m_length:要签名的数据长度
			- 0 < m_length <= 密钥长度 - 11
		-sigret:传出，存储了签名之后的数据->密文
		-siglen:sigret密文长度
		-rsa:私钥
	返回值：
		== 1成功
		！= 1失败
*/

//验证签名        
int RSA_verify(int type, const unsigned char *m, unsigned int m_length,
               const unsigned char *sigbuf, unsigned int siglen, RSA *rsa);
/*
	参数：
		-type:使用的哈希算法
			-NID_MD5
			-NID_SHA1
		-m:要进行签名的原始数据->接收到的
		-m_length:要签名的原始数据长度
			- 0 < m_length <= 密钥长度 - 11
		-sigbuf:接收到的签名数据
		-siglen:接收到的签名数据长度
		-rsa:公钥
	返回值：
		== 1成功
		！= 1失败
*/

```

# 三、对称加密

## 1、特点

- 分组加密：每组长度-->16byte，128bit
- 密钥长度：16byte，24byte，32byte
- 每组的明文和加密之后的密文长度相同



## 2、AES

> ASE是一套对称密钥的密码术，目前已广泛使用，用于替代已经不够安全的DES算法。所称对称加密，就是说如果加密和解密使用同一个密钥，消息的发送方和接收方在消息传递前需要享有这个密钥。和非对称密钥体系不同，这里的密钥是双方保密的，不会让任何第三方知道。
>
> 对称密钥加密算法主要**基于块加密，选取固定长度的密钥**，去**加密明文中的固定长度的块，生成的密文块和明文块长度一样。**显然密钥长度十分重要，块的长度也很重要。如果太短，则很容易枚举出所有的明文-密文映射；如果太长，性能则会加剧下降。AES中规定块长度为128bit，而密钥长度可以选择128,192或256bit。暴力破解密钥需要上完亿，这保证了AES的安全性。



OpenSSL中AES加解密的API

### （1）生成加密/解密的Key



```c++
#include <openssl/ase.h>
#define AES_BLOCK_SIZE 16 //明文分组的大小
//加密的时候调用
//aes中的密钥格式 AES_KEY

//aes设置加密密钥
int AES_set_encrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
/*
	参数：
		-userKey：对称加密的密钥 16byte，24byte，32byte
		-bits：指定的密钥长度，单位bit
		-key：传出参数
*/
//aes设置解密密钥	         
int AES_set_decrypt_key(const unsigned char *userKey, const int bits,
                        AES_KEY *key);
                        

```



### （2）CBC方式加密-密码分组连接模式

```c++
//ase CBC 加解密都用这个
void AES_cbc_encrypt(const unsigned char *in, unsigned char *out,
                     size_t length, const AES_KEY *key,
                     unsigned char *ivec, const int enc);

/*
	参数：
		- in：要加密/解密的数据
		- out：传出参数
			- 加密：存储密文
			- 解密：存储明文
		- length：修改第一个参数in的长度
			- len = (字符串长度 + \0) % 16 == 0
			- 如果不是16整数倍，函数内部自己填充
				- 实际长度：((len / 16 ) + 1) * 16
		- enc：指定数据要解密还是加密
			-# define AES_ENCRYPT     1 加密
			-# define AES_DECRYPT     0 解密
		- key：初始化之后的秘钥
		- ivec：初始化向量，SSSS字符串==>长度和分组长度相同

*/
```

## 3、密码分组模式

- ECB 电子密码本模式
  - 最不推荐，明文分组加密之后直接的到密文分组，容易被找到规律破解。
- CBC 密码分组连接模式（最常用）
  - 明文分组之后，与**初始化向量（字符串与明文长度一致）**做位运算，然后加密，得到密文分组。
- CFB 密文反馈模式
  - 明文分组之后，初始化向量加密，与明文分组作位运算，得到密文分组。
- CFB 输出反馈模式
  - 明文分组之后，初始化向量每次与明文分组位运算得到密钥分组之前，对密文分组进行一次加密。
- CTR 计数器模式
  - i = 0
  - 明文分组之后，计数器（随机数+ i + 1）加密，与明文分组进行位运算，得到密文分组。



# 四、其他

- OPENSSL_Uplink_no_OPENSSL_Applink 错误

`Applink()函数不属于openss的dll内部函数的一部分（通过dll分析器看出这个函数不存在）所以不必须把applink.c文件应用程序的一部分编译`

```
extern "C"
{
#include<openssl/applink.c>
}
```

