#ifndef LBCRYPTO_CRYPTO_RGSWOPS_C
#define LBCRYPTO_CRYPTO_RGSWOPS_C

#include "RingGSWOPS.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

RGSWOps::RGSWOps(){

}

RGSWKeyPair RGSWOps::KeyGen(const shared_ptr<LPCryptoParameters<Poly>> cryptoParams) {

	const shared_ptr<LPCryptoParametersBGV<Poly>> cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Poly>>(cryptoParams);

	RGSWKeyPair	kp(cryptoParamsBGV);

	const shared_ptr<ILParams> elementParams = cryptoParamsBGV->GetElementParams();

	const auto p = cryptoParamsBGV->GetPlaintextModulus();

	const DiscreteGaussianGenerator &dgg = cryptoParamsBGV->GetDiscreteGaussianGenerator();

	DiscreteUniformGenerator dug;


	usint n = kp.secretKey->GetSecretKey().GetModulus().GetLengthForBase(p);

	//Generate the secret key
	Poly s(dgg, elementParams, Format::COEFFICIENT);

	s.SwitchFormat();

	for(usint i=0;i<n;i++){
		//Generate the uniformly random element "a" of the public key
		Poly a(dug, elementParams, Format::EVALUATION);

		Poly e(dgg, elementParams, Format::COEFFICIENT);
		e.SwitchFormat();

		Poly b = a*s + p*e;

		kp.publicKey->SetAPublicElementAtIndex(i, std::move(a));

		kp.publicKey->SetBPublicElementAtIndex(i, std::move(b));

	}

	kp.secretKey->SetSecretKey(std::move(s));

	return kp;

}

std::shared_ptr<RGSWCiphertext> RGSWOps::Encrypt(const RGSWPublicKey &pk, Poly &m) {

	const shared_ptr<LPCryptoParametersBGV<Poly>> cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Poly>>(pk.GetCryptoParameters());

	shared_ptr<RGSWCiphertext> ciphertext(new RGSWCiphertext());

	const shared_ptr<ILParams> elementParams = cryptoParamsBGV->GetElementParams();

	const auto p = cryptoParamsBGV->GetPlaintextModulus();

	const DiscreteGaussianGenerator &dgg = cryptoParamsBGV->GetDiscreteGaussianGenerator();

	m.SwitchFormat();

	usint n = pk.GetPublicElements().size();

	Poly v(dgg, elementParams, Format::EVALUATION);

	for(usint i=0;i<n;i++){

		const Poly &a = pk.GetAPublicElementsAtIndex(i);
		const Poly &b = pk.GetBPublicElementsAtIndex(i);

		Poly e0(dgg, elementParams, Format::EVALUATION);
		Poly e1(dgg, elementParams, Format::EVALUATION);

		Poly c0(b*v + p*e0 + m);

		Poly c1(a*v + p*e1);

		ciphertext->GetElements().at(i).SetA(std::move(c1));
		ciphertext->GetElements().at(i).SetB(std::move(c0));

	}

	return ciphertext;
}

Poly RGSWOps::Decrypt(const RGSWCiphertext& ciphertext, const Poly& sk) {
	Poly result;
	return result;
}
RGSWCiphertext RGSWOps::Add(const RGSWCiphertext& a, const RGSWCiphertext& b) {
	RGSWCiphertext result;
	return result;
}

RGSWCiphertext RGSWOps::ScalarMultiply(const BigInteger &a,const RGSWCiphertext& ciphertext) {
	RGSWCiphertext result;
	return result;
}
RGSWCiphertext RGSWOps::RingMultiply(const Poly& a, const RGSWCiphertext& ciphertext) {
	RGSWCiphertext result;
	return result;
}
RGSWCiphertext RGSWOps::Multiply(const RGSWCiphertext& a, const RGSWCiphertext& b) {
	RGSWCiphertext result;
	return result;
}

}
#endif
