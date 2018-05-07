#ifndef LBCRYPTO_CRYPTO_RGSWOPS_H
#define LBCRYPTO_CRYPTO_RGSWOPS_H

//Includes Section
#include "palisade.h"
#include "ringgsw.h"
#include "rlwe.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class RGSWOps{
	public:
	RGSWOps();
	static RGSWKeyPair KeyGen(const shared_ptr<LPCryptoParameters<Poly>> cryptoParams);
	static std::shared_ptr<RGSWCiphertext> Encrypt(const RGSWPublicKey &pk, Poly &m);
	static Poly Decrypt(const RGSWCiphertext& ciphertext,const Poly& sk);
	static RGSWCiphertext Add(const RGSWCiphertext& a,const RGSWCiphertext& b);
	static RGSWCiphertext ScalarMultiply(const BigInteger &a,const RGSWCiphertext& ciphertext);
	static RGSWCiphertext RingMultiply(const Poly& a, const RGSWCiphertext& ciphertext);
	static RGSWCiphertext Multiply(const RGSWCiphertext& a,const RGSWCiphertext& b);
};


}

#endif
