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

	usint base = cryptoParamsBGV->GetRelinWindow();

	usint n = elementParams->GetModulus().GetMSB();

	n = std::ceil(n/base);

	//Generate the secret key
	Poly s(dgg, elementParams, Format::COEFFICIENT);

	s.SwitchFormat();

	for(usint i=0;i<n;i++){
		//Generate the uniformly random element "a" of the public key
		Poly a(dug, elementParams, Format::EVALUATION);

		Poly e(dgg, elementParams, Format::EVALUATION);

		Poly b = a*s + p*e;

		kp.publicKey->SetPublicElementAtIndex(i, std::move(a),std::move(b));

	}

	kp.secretKey->SetSecretKey(std::move(s));

	return kp;

}

std::shared_ptr<RGSWCiphertext> RGSWOps::Encrypt(const RGSWPublicKey &pk, Poly &m) {

	const shared_ptr<LPCryptoParametersBGV<Poly>> cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Poly>>(pk.GetCryptoParameters());

	shared_ptr<RGSWCiphertext> ciphertext(new RGSWCiphertext(cryptoParamsBGV));

	const shared_ptr<ILParams> elementParams = cryptoParamsBGV->GetElementParams();

	const auto p = cryptoParamsBGV->GetPlaintextModulus();

	const DiscreteGaussianGenerator &dgg = cryptoParamsBGV->GetDiscreteGaussianGenerator();

	m.SwitchFormat();

	usint n = pk.GetPublicElements().size();

	usint r = cryptoParamsBGV->GetRelinWindow();

	BigInteger powersOfBaseInit(1);//2^r

	Poly v(dgg, elementParams, Format::EVALUATION);

	for(usint i=0;i<n;i++){

		const Poly &a = pk.GetAPublicElementsAtIndex(i);
		const Poly &b = pk.GetBPublicElementsAtIndex(i);

		Poly e0(dgg, elementParams, Format::EVALUATION);
		Poly e1(dgg, elementParams, Format::EVALUATION);

		Poly c0(b*v + p*e0 + m*(powersOfBaseInit<<(r*i)));

		Poly c1(a*v + p*e1);

		ciphertext->SetElementAtIndex(i,std::move(c1),std::move(c0));

	}

	return ciphertext;
}

Poly RGSWOps::Decrypt(const std::shared_ptr<RGSWCiphertext> ciphertext,const std::shared_ptr<RGSWSecretKey> sk) {
	Poly result;
	//std::vector<Poly> toShowAsOutput;

	const auto cryptoParams = sk->GetCryptoParameters();
	const auto p = cryptoParams->GetPlaintextModulus();
	const auto &c = ciphertext->GetElements();
	const auto &s = sk->GetSecretKey();

	Poly b = c[0].GetB() - s * c[0].GetA();

	b.SwitchFormat();

	result = b.Mod(p);

	for(usint i=1;i<ciphertext->GetElements().size();i++){
		b = c[i].GetB()-s*c[i].GetA();
		b.SwitchFormat();
		std::cout<< b<<'\n';
	}


	return result;
}
RGSWCiphertext RGSWOps::Add(const RGSWCiphertext& a, const RGSWCiphertext& b) {
	RGSWCiphertext result(a.GetCryptoParameters());
	return result;
}

std::shared_ptr<RGSWCiphertext> RGSWOps::ScalarMultiply(const BigInteger &a,const std::shared_ptr<RGSWCiphertext> ciphertext) {
	const auto cryptoParams = ciphertext->GetCryptoParameters();
	auto result = make_shared<RGSWCiphertext>(cryptoParams);
	auto logQ = ciphertext->GetElements().size();
	auto r = cryptoParams->GetRelinWindow();
	auto base = 1<<r;

	for(usint i=0;i<logQ;i++){
		BigInteger scalarValue = a<<(i*r);
		usint digit = scalarValue.GetDigitAtIndexForBase(1,base);
		Poly a = BigInteger(digit)*ciphertext->GetElements().at(0).GetA();
		Poly b = BigInteger(digit)*ciphertext->GetElements().at(0).GetB();
		for(usint j=1;j<logQ;j++){
			digit = scalarValue.GetDigitAtIndexForBase(j+1,base);
			a+= BigInteger(digit)*ciphertext->GetElements().at(j).GetA();
			b+= BigInteger(digit)*ciphertext->GetElements().at(j).GetB();
		}
		result->SetElementAtIndex(i,std::move(a),std::move(b));
	}
	return result;
}
RGSWCiphertext RGSWOps::RingMultiply(const Poly& a, const RGSWCiphertext& ciphertext) {
	RGSWCiphertext result(ciphertext.GetCryptoParameters());
	return result;
}
RGSWCiphertext RGSWOps::Multiply(const RGSWCiphertext& a, const RGSWCiphertext& b) {
	RGSWCiphertext result(a.GetCryptoParameters());
	//decompose b
	/*for(int i=0;i<b.GetElements().size();i++){
		const Poly& a = b.GetElements().GetA();
		const Poly& b = b.GetElements().GetB();

	}*/
	return result;
}

}
#endif
