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

template <class Element>
class RGSWOps{
	public:
	RGSWOps();
	static RGSWKeyPair<Element> KeyGen(const shared_ptr<LPCryptoParameters<Element>> cryptoParams);
	static std::shared_ptr<RGSWCiphertext<Element>> Encrypt(const RGSWPublicKey<Element> &pk, Element &m);
	static std::shared_ptr<RGSWCiphertext<Element>> ClearEncrypt(const RGSWPublicKey<Element> &pk, Element &m);
	static Element Decrypt(const std::shared_ptr<RGSWCiphertext<Element>> ciphertext,const std::shared_ptr<RGSWSecretKey<Element>> sk);
	static RGSWCiphertext<Element> Add(const RGSWCiphertext<Element>& a,const RGSWCiphertext<Element>& b);
	static std::shared_ptr<RGSWCiphertext<Element>> ScalarMultiply(const BigInteger &a,const std::shared_ptr<RGSWCiphertext<Element>> ciphertext);
	static std::shared_ptr<RGSWCiphertext<Element>> RingMultiply(const Element& a, const std::shared_ptr<RGSWCiphertext<Element>> cipher);
	static std::shared_ptr<RGSWCiphertext<Element>> Multiply(const std::shared_ptr<RGSWCiphertext<Element>> a, const std::shared_ptr<RGSWCiphertext<Element>> b);
};


}

#endif
