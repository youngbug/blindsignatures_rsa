#include "blindsignatures_rsa.h"
#include <mbedtls/rsa.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/bignum.h>

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


	//1.Generate RSA key pairs.
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

	//2.Blind message.
	printf("2. Blind message.\r\n");
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
	/*if ((ret = mbedtls_mpi_read_binary(&e, "\x00\x01\x00\x01", 4)) != 0)
	{
		printf("mbedtls_mpi_read_binary failed ret=%08X\r\n", ret);
		goto EXIT;
	}*/
	if ((ret = blindsignature_hide_message(&m, &blind_factor, &rsa.private_E, &rsa.private_N, &blind_message)) != 0)
	{
		printf("blindsignature_hide_message failed ret=%08X\r\n", ret);
		goto EXIT;
	}

	//3.Calculate blind signature
	printf("Calculate blind signature.\r\n");
	if ((ret = blindsignature_sign(&blind_message, &rsa.private_D, &rsa.private_N, &signature)) != 0)
	{
		printf("blindsignature_sign failed ret=%08X\r\n", ret);
		goto EXIT;
	}

	//4.Unblind signature
	printf("Unblind signature\r\n");
	if ((ret = blindsignature_unblind_sign(&signature, &blind_factor, &rsa.private_N, &signature)) != 0)
	{
		printf("Unblind signature: blindsignature_unblind_sign failed ret=%08X\r\n", ret);
		goto EXIT;
	}
	
	memset(buffer1, 0, 128);
	mbedtls_mpi_write_binary(&signature, buffer1, 128);

	//5.Check signature
	printf("Calculate signature.\r\n");
	mbedtls_mpi_init(&signature);
	if ((ret = blindsignature_sign(&m, &rsa.private_D, &rsa.private_N, &signature)) != 0)
	{
		printf("blindsignature_sign failed ret=%08X\r\n", ret);
		goto EXIT;
	}
	memset(buffer2, 0, 128);
	mbedtls_mpi_write_binary(&signature, buffer2, 128);

EXIT:
	mbedtls_rsa_free(&rsa);
	mbedtls_mpi_free(&m); mbedtls_mpi_free(&blind_factor);
	mbedtls_mpi_free(&e); mbedtls_mpi_free(&blind_message); mbedtls_mpi_free(&signature);

	return 0;
}