// SPDX-License-Identifier: MIT

#include <stdlib.h>

#include <oqs/kem_ml_kem.h>

#if defined(OQS_ENABLE_KEM_ml_kem_768)

OQS_KEM *OQS_KEM_ml_kem_768_new(void) {

	OQS_KEM *kem = OQS_MEM_malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = OQS_KEM_alg_ml_kem_768;
	kem->alg_version = "FIPS203";

	kem->claimed_nist_level = 3;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_ml_kem_768_length_public_key;
	kem->length_secret_key = OQS_KEM_ml_kem_768_length_secret_key;
	kem->length_ciphertext = OQS_KEM_ml_kem_768_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_ml_kem_768_length_shared_secret;

	kem->keypair = OQS_KEM_ml_kem_768_keypair;
	kem->encaps = OQS_KEM_ml_kem_768_encaps;
	kem->decaps = OQS_KEM_ml_kem_768_decaps;

	return kem;
}

extern int PQCP_MLKEM_NATIVE_MLKEM768_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCP_MLKEM_NATIVE_MLKEM768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCP_MLKEM_NATIVE_MLKEM768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

OQS_API OQS_STATUS OQS_KEM_ml_kem_768_keypair(uint8_t *public_key, uint8_t *secret_key) {
	return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_keypair(public_key, secret_key);
}

OQS_API OQS_STATUS OQS_KEM_ml_kem_768_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
	return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_enc(ciphertext, shared_secret, public_key);
}

OQS_API OQS_STATUS OQS_KEM_ml_kem_768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
	return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_dec(shared_secret, ciphertext, secret_key);
}

#endif
