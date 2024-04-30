#include "./wrapper.h"
#include "./params.h"
#include "./api.h"
#include "./sign.h"
#include "./poly.h"
#include <string.h>

#if DILITHIUM_PUBLIC_KEY_SIZE != CRYPTO_PUBLICKEYBYTES
#error invalid public key size, update me!
#endif
#if DILITHIUM_PRIVATE_KEY_SIZE != CRYPTO_SECRETKEYBYTES
#error invalid private key size, update me!
#endif
#if DILITHIUM_SIGNATURE_SIZE != CRYPTO_BYTES
#error invalid signature size, update me!
#endif

int getDilithiumAlgorithmVariant() {
	return DILITHIUM_MODE;
}

uint8_t* DilithiumState_getPrivateKey(DilithiumState* self) {
	return self->m_sk;
}

uint8_t* DilithiumState_getPublicKey(DilithiumState* self) {
	return self->m_pk;
}

uint8_t* DilithiumState_getScratchPad(DilithiumState* self) {
	return self->m_scratchpad;
}

int DilithiumState_verify(const DilithiumState* self, uint8_t *signedMessage) {
	size_t messageLength = DILITHIUM_MESSAGE_SIZE;
	return crypto_sign_open(signedMessage, &messageLength, signedMessage, DILITHIUM_SIGNED_MESSAGE_SIZE, self->m_pk);
}

int DilithiumState_sign(const DilithiumState* self, uint8_t* signature, const uint8_t* message) {
	size_t signatureSize = DILITHIUM_SIGNATURE_SIZE;
	return crypto_sign_signature(signature, &signatureSize, message, DILITHIUM_MESSAGE_SIZE, self->m_sk);
}

uint8_t* DilithiumNtt(const uint8_t* coeff_int_domain){
	uint8_t* coeff_ntt_domain;
	poly c;

	polyntt_unpack(&c, coeff_int_domain);
	//poly_ntt(&c);
	polyntt_pack(coeff_ntt_domain, &c);
	return coeff_ntt_domain;
}
