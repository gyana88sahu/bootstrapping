#ifndef SRC_BGV_H
#define SRC_BGV_H

#include "palisade.h"
#include "pubkeylp.h"
#include "cryptocontext.h"

namespace lbcrypto{

class BGVScheme {
public:
	BGVScheme();

	LPKeyPair<Poly> KeyGen(CryptoContext<Poly> cc);

	Ciphertext<Poly> Encrypt(const LPPublicKey<Poly> publicKey, Poly &plaintext) const;

	DecryptResult Decrypt(const LPPrivateKey<Poly> privateKey,
				const Ciphertext<Poly> ciphertext,
				NativePoly *plaintext) const;

	Ciphertext<Poly> Encrypt(const LPPublicKey<Poly> publicKey, const std::vector<int64_t> &input) const;

	Poly Encode(const LPPublicKey<Poly> publicKey, const std::vector<int64_t> &input) const;

	virtual ~BGVScheme();
};

class BGVOps  {

private:

	static std::vector<LPEvalKey<Poly>> multKey;


	public:

		BGVOps() {}

		void GenEvalMultKey(const LPPrivateKey<Poly> key);

		Ciphertext<Poly> EvalAdd(const Ciphertext<Poly> ciphertext1,
			const Ciphertext<Poly> ciphertext2) const;


		Ciphertext<Poly> EvalAdd(const Ciphertext<Poly> ciphertext,
			const Plaintext plaintext) const;

		Ciphertext<Poly> EvalSub(const Ciphertext<Poly> ciphertext1,
			const Ciphertext<Poly> ciphertext2) const;

		Ciphertext<Poly> EvalSub(const Ciphertext<Poly> ciphertext1,
				const Plaintext plaintext) const;

		Ciphertext<Poly> EvalMult(const Ciphertext<Poly> ciphertext1,
					const Ciphertext<Poly> ciphertext2) const;

		Ciphertext<Poly> EvalMultInternal(const Ciphertext<Poly> ciphertext1,
			const Ciphertext<Poly> ciphertext2) const;

		Ciphertext<Poly> EvalMultInternal(const Ciphertext<Poly> ciphertext,
			const Plaintext plaintext) const;

		Ciphertext<Poly> EvalMult(const Ciphertext<Poly> ciphertext1,
			const Ciphertext<Poly> ciphertext2,
			const LPEvalKey<Poly> ek) const;

		LPEvalKey<Poly> KeySwitchGen(const LPPrivateKey<Poly> originalPrivateKey,
					const LPPrivateKey<Poly> newPrivateKey) const;

		Ciphertext<Poly> KeySwitch(const LPEvalKey<Poly> keySwitchHint,
					const Ciphertext<Poly> cipherText) const;

		LPEvalKey<Poly> EvalMultKeyGen(const LPPrivateKey<Poly> originalPrivateKey) const;
};


}
#endif /* SRC_BGV_H_ */
