# blindsignatures_rsa

[English](README.md) | 中文

这个项目是基于mbedTLS大数运算库实现的RSA盲签名算法。

## 简介
盲签名算法方案包含双方，用户Alice（信息的拥有者）希望对他的消息进行签名，签名者Bob（不允许他知道信息的具体内容）控制着签名私钥。Alice可以在Bob不获知消息具体内容的前提下，让Bob完成对消息的签名。

## RSA盲签名
RSA盲签名是盲签名方案中一个最简单的实现。

步骤：

- Alice选择一个随机数k
- Alice对原始的消息进行计算，$m' = m k^e (mod \ n)$ 并把计算后（盲化）的消息 $m'$发送给Bob
- Bob计算 $s' = (m')^d (mod \ n)$ 并把计算后的签名值 $s'$ 发送给Alice
- Alice计算 $s = s'k^{-1} (mod \ n)$，$s$ 就是Bob对原始消息 $m$的数字签名


## 依赖

这个实现需要mbedTLS 3.0

## 用法

```c
#include "blindsignatures_rsa.h"

int main()
{
	int ret;
	mbedtls_rsa_context rsa;
	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;
	const char* pers = "rsa_blindsignature";
	mbedtls_mpi m, blind_factor, e, blind_message,signature;

	unsigned char buffer1[128];
	unsigned char buffer2[128];

	unsigned char message_buffer [] = {0x00, 0x01, 0x08, 0x0A, 0x0B, 0x03, 0x08, 0x02};
	unsigned char blind_factor_buffer[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	
	mbedtls_rsa_init(&rsa);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_mpi_init(&m); mbedtls_mpi_init(&blind_factor);
	mbedtls_mpi_init(&e); mbedtls_mpi_init(&blind_message); mbedtls_mpi_init(&signature);


	//1.生成RSA密钥对.
	printf("\r\n1. Generate RSA key pairs.\r\n");
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
		(const unsigned char*)pers,
		strlen(pers))) != 0)
	{
		printf("mbedtls_ctr_drbg_seed failed ret=%08X\r\n", ret);
		goto EXIT;
	}
	if ((ret = mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr_drbg, 1024,
		65537)) != 0)
	{
		printf("mbedtls_rsa_gen_key failed ret=%08X\r\n", ret);
		goto EXIT;
	}

	//2.盲化原始消息.
	if ((ret = mbedtls_mpi_read_binary(&m, message_buffer, 8)) != 0)
	{
		printf("mbedtls_mpi_read_binary failed ret=%08X\r\n", ret);
		goto EXIT;
	}
	if ((ret = mbedtls_mpi_read_binary(&blind_factor, blind_factor_buffer, 8)) != 0)
	{
		printf("mbedtls_mpi_read_binary failed ret=%08X\r\n", ret);
		goto EXIT;
	}

	if ((ret = blindsignature_hide_message(&m, &blind_factor, &rsa.private_E, &rsa.private_N, &blind_message)) != 0)
	{
		printf("blindsignature_hide_message failed ret=%08X\r\n", ret);
		goto EXIT;
	}

	//3.签名方计算签名
	printf("3.Calculate blind signature.\r\n");
	if ((ret = blindsignature_sign(&blind_message, &rsa.private_D, &rsa.private_N, &signature)) != 0)
	{
		printf("blindsignature_sign failed ret=%08X\r\n", ret);
		goto EXIT;
	}

	//4.消息持有方去盲化获得真正的签名
	printf("4.Unblind signature\r\n");
	if ((ret = blindsignature_unblind_sign(&signature, &blind_factor, &rsa.private_N, &signature)) != 0)
	{
		printf("Unblind signature: blindsignature_unblind_sign failed ret=%08X\r\n", ret);
		goto EXIT;
	}


EXIT:
	mbedtls_rsa_free(&rsa);
	mbedtls_mpi_free(&m); mbedtls_mpi_free(&blind_factor);
	mbedtls_mpi_free(&e); mbedtls_mpi_free(&blind_message); mbedtls_mpi_free(&signature);

	return 0;
}
```