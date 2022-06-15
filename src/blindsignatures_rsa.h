#ifndef  __BLINDSIGNATURES_RSA_C__
#define __BLINDSIGNATURES_RSA_C__
#include <mbedtls/bignum.h>

int blindsignature_hide_message(mbedtls_mpi* m, mbedtls_mpi* blind_factor, mbedtls_mpi* e, mbedtls_mpi* n, mbedtls_mpi* blind_message);
int blindsignature_sign(mbedtls_mpi* blind_message, mbedtls_mpi* d, mbedtls_mpi* n, mbedtls_mpi* s);
int blindsignature_unblind_sign(mbedtls_mpi* blind_signature, mbedtls_mpi* blind_factor, mbedtls_mpi* n, mbedtls_mpi* signature);
#endif // ! __BLINDSIGNATURES_RSA_C__
