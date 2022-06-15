#include "blindsignatures_rsa.h"


int blindsignature_hide_message(mbedtls_mpi* m, mbedtls_mpi* blind_factor, mbedtls_mpi* e, mbedtls_mpi* n, mbedtls_mpi* blind_message)
{
	int ret;
	mbedtls_mpi r;
	mbedtls_mpi_init(&r);

	// r = blind_factor ^ e mod n
	if ((ret = mbedtls_mpi_exp_mod(&r, blind_factor, e, n, NULL) ) != 0)
	{
		printf("Hide message: mbedtls_mpi_mod_init failed ret=%8X\r\n", ret);
		goto EXIT;
	}
	// m1 = m * r
	if ((ret = mbedtls_mpi_mul_mpi(blind_message, m, &r)) != 0)
	{
		printf("Hide message: mbedtls_mpi_mul_mpi failed ret=%08X\r\n", ret);
		goto EXIT;
	}
	// blind_message = m1 mod n
	if ((ret = mbedtls_mpi_mod_mpi(blind_message, blind_message, n)) != 0)
	{
		printf("Hide message: mbedtls_mpi_mod_mpi failed ret=%08X\r\n", ret);
		goto EXIT;
	}
EXIT:
	mbedtls_mpi_free(&r);
	return 0;
}

int blindsignature_sign(mbedtls_mpi* blind_message, mbedtls_mpi* d, mbedtls_mpi* n, mbedtls_mpi* s)
{
	int ret;
	mbedtls_mpi r;

	//s = m ^d mod n
	if ((ret = mbedtls_mpi_exp_mod(s, blind_message, d, n, NULL)) != 0)
	{
		printf("Blind signature: mbedtls_mpi_exp_mod failed ret=%08X\r\n", ret);
		goto EXIT;
	}
EXIT:
	return 0;
}

int blindsignature_unblind_sign(mbedtls_mpi* blind_signature, mbedtls_mpi* blind_factor, mbedtls_mpi* n, mbedtls_mpi* signature)
{
	int ret;
	mbedtls_mpi inv_blind_factor;

	mbedtls_mpi_init(&inv_blind_factor);

	if ((ret = mbedtls_mpi_inv_mod(&inv_blind_factor, blind_factor, n)) != 0)
	{
		printf("Unblind signature: mbedtls_mpi_inv_mod failed ret=%08X\r\n", ret);
		goto EXIT;
	}

	if ((ret = mbedtls_mpi_mul_mpi(signature, &inv_blind_factor, blind_signature)) != 0)
	{
		printf("Unblind signature: mbedtls_mpi_mul_mpi failed ret=%08X\r\n", ret);
		goto EXIT;
	}

	if ((ret = mbedtls_mpi_mod_mpi(signature, signature, n)) != 0)
	{
		printf("Unblind signature: mbedtls_mpi_mod_mpi failed ret=%08X\r\n", ret);
		goto EXIT;
	}
EXIT:
	mbedtls_mpi_free(&inv_blind_factor);
	return 0;
}