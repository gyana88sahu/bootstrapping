#ifndef LBCRYPTO_CRYPTO_ISTANDARDLWEOPS_H
#define LBCRYPTO_CRYPTO_ISTANDARDLWEOPS_H

#include "integerlwedefs.h"

namespace lbcrypto{

class ISLWEOps{
public:

	static ILWEKeyPair KeyGen(const shared_ptr<ILWEParams> &param);

	static shared_ptr<ILWECiphertext> Encrypt(const ILWEPublicKey &pk, usint m);

	static usint Decrypt(const shared_ptr<ILWECiphertext> cipher, const ILWESecretKey &sk);

	static void KeySwitchGen(const ILWESecretKey &sk);

	static shared_ptr<ILWECiphertext> EvalMult(const shared_ptr<ILWECiphertext> c1, const shared_ptr<ILWECiphertext> c2);

};

}

#endif
