#ifndef LBCRYPTO_CRYPTO_RGSW_H
#define LBCRYPTO_CRYPTO_RGSW_H

//Includes Section
#include "palisade.h"
#include "rlwe.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
//Definations of core classes of RingGSW
namespace lbcrypto {
//forward declarations

class RGSWKey;

class LWEForm {

private:
	Poly a;
	Poly b;

public:

	LWEForm(const Poly& a, const Poly &b);

	LWEForm(Poly &&a, Poly &&b);

	LWEForm(const shared_ptr<LPCryptoParameters<Poly>> params);

	const Poly& GetA() const;

	void SetA(const Poly& a);

	void SetA(Poly &&a);

	const Poly& GetB() const;

	void SetB(const Poly& b);

	void SetB(Poly &&b);

	void SwitchFormat();

};

class RGSWKey {

private:
	std::shared_ptr<LPCryptoParameters<Poly>> cryptoParams;

public:

	RGSWKey(const std::shared_ptr<LPCryptoParameters<Poly>> params);

	const std::shared_ptr<LPCryptoParameters<Poly>> GetCryptoParameters() const;
};

//ciphertext of ring gsw form
class RGSWCiphertext: public RGSWKey {

private:
	std::vector<LWEForm> m_element;

public:

	RGSWCiphertext(const shared_ptr<LPCryptoParameters<Poly>> params);

	const std::vector<LWEForm>& GetElements() const;

	void SetElementAtIndex(usint idx, const Poly &valueB, const Poly& valueA);

	void SetElementAtIndex(usint idx, Poly &&valueB, Poly &&valueA);

	void SwitchFormat();
};

class RGSWPublicKey: public RGSWKey {

private:
	shared_ptr<LWEForm> m_elements;

public:
	RGSWPublicKey(const shared_ptr<LPCryptoParameters<Poly>> params);

	const LWEForm& GetPublicElements() const;

	void SetPublicElements(const Poly &a,const Poly &b);

	void SetPublicElements(Poly &&a, Poly &&b);

};

class RGSWSecretKey: public RGSWKey {
private:
	std::shared_ptr<Poly> m_sk;

public:
	RGSWSecretKey(const shared_ptr<LPCryptoParameters<Poly>> params);

	const Poly& GetSecretKey();
	void SetSecretKey(const Poly& value);
	void SetSecretKey(Poly &&value);
};

class RGSWKeyPair {
public:
	std::shared_ptr<RGSWSecretKey> secretKey;
	std::shared_ptr<RGSWPublicKey> publicKey;

	RGSWKeyPair(const shared_ptr<LPCryptoParameters<Poly>> params);
};

}
#endif
