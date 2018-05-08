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

class LWEForm;
class RGSWCiphertext;
class RGSWPublicKey;
class RGSWSecretKey;
class RGSWKey;
class RGSWKeyPair;

class LWEForm {

private:
	Poly a;
	Poly b;

public:

	LWEForm(const Poly& a, const Poly &b);

	LWEForm(Poly &&a, Poly &&b);

	const Poly& GetA() const;

	void SetA(const Poly& a);

	void SetA(Poly &&a);

	const Poly& GetB() const;

	void SetB(const Poly& b);

	void SetB(Poly &&b);

	void SwitchFormat();

};

//ciphertext of ring gsw form
class RGSWCiphertext {

private:
	std::vector<LWEForm> m_element;

public:

	std::vector<LWEForm>& GetElements();

	void SetElementAtIndex(usint idx, const Poly &valueA, const Poly& valueB);

	void SetElementAtIndex(usint idx, Poly &&valueA, Poly &&valueB);

	void SwitchFormat();
};

class RGSWKey {

private:
	std::shared_ptr<LPCryptoParameters<Poly>> cryptoParams;

public:

	RGSWKey(const std::shared_ptr<LPCryptoParameters<Poly>> params);

	const std::shared_ptr<LPCryptoParameters<Poly>> GetCryptoParameters() const;
};

class RGSWPublicKey: public RGSWKey {

private:
	std::vector<LWEForm> m_elements;

public:
	RGSWPublicKey(const shared_ptr<LPCryptoParametersRLWE<Poly>> params): RGSWKey(params){};

	const std::vector<LWEForm>& GetPublicElements() const;

	const Poly& GetAPublicElementsAtIndex(usint idx) const;

	const Poly& GetBPublicElementsAtIndex(usint idx) const;

	void SetAPublicElementAtIndex(usint idx, const Poly& value);

	void SetAPublicElementAtIndex(usint idx, Poly &&value);

	void SetBPublicElementAtIndex(usint idx, const Poly& value);

	void SetBPublicElementAtIndex(usint idx, Poly &&value);

	void SetPublicElementAtIndex(usint idx, const Poly &valueA, const Poly &valueB);

	void SetPublicElementAtIndex(usint idx, Poly &&valueA, Poly &&valueB);

};

class RGSWSecretKey: public RGSWKey {
private:
	std::shared_ptr<Poly> m_sk;

public:
	RGSWSecretKey(const shared_ptr<LPCryptoParametersRLWE<Poly>> params): RGSWKey(params){
		m_sk = std::make_shared<Poly>(params->GetElementParams(),COEFFICIENT,true);
	};

	const Poly& GetSecretKey();
	void SetSecretKey(const Poly& value);
	void SetSecretKey(Poly &&value);
};

class RGSWKeyPair {
public:
	std::shared_ptr<RGSWSecretKey> secretKey;
	std::shared_ptr<RGSWPublicKey> publicKey;

	RGSWKeyPair(const shared_ptr<LPCryptoParametersRLWE<Poly>> params);
};

}
#endif
