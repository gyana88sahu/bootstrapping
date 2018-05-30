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

	RGSWKeyPair	kp(cryptoParams);

	const shared_ptr<ILParams> elementParams = cryptoParamsBGV->GetElementParams();

	const auto p = cryptoParamsBGV->GetPlaintextModulus();

	const auto &dgg = cryptoParamsBGV->GetDiscreteGaussianGenerator();

	DiscreteUniformGenerator dug;

	//Generate the secret key
	Poly s(dgg, elementParams, Format::COEFFICIENT);

	s.SwitchFormat();

	//Generate the uniformly random element "a" of the public key
	Poly a(dug, elementParams, Format::EVALUATION);

	Poly e(dgg, elementParams, Format::EVALUATION);

	Poly b = a*s + p*e;

	kp.publicKey->SetPublicElements(std::move(a),std::move(b));

	kp.secretKey->SetSecretKey(std::move(s));

	return kp;

}

std::shared_ptr<RGSWCiphertext> RGSWOps::Encrypt(const RGSWPublicKey &pk, Poly &m) {

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Poly>>(pk.GetCryptoParameters());

	shared_ptr<RGSWCiphertext> ciphertext = std::make_shared<RGSWCiphertext>(cryptoParamsBGV);

	const shared_ptr<ILParams> elementParams = cryptoParamsBGV->GetElementParams();

	const auto p = cryptoParamsBGV->GetPlaintextModulus();

	const Poly::TugType tug;

	m.SwitchFormat();

	usint base = cryptoParamsBGV->GetRelinWindow();

	usint l = elementParams->GetModulus().GetMSB();

	l = std::ceil((double)l/(double)base);

	BigInteger powersOfBaseInit(1);//2^r

	const Poly &a = pk.GetPublicElements().GetA();
	const Poly &b = pk.GetPublicElements().GetB();

	for (usint i = 0; i < l; i++) {

		Poly r(tug, elementParams, Format::EVALUATION); //r is the random noise

		Poly e0(tug, elementParams, Format::EVALUATION);

		Poly e1(tug, elementParams, Format::EVALUATION);

		Poly bPoly(b * r + p*e1 + m * (powersOfBaseInit << (base * i)));

		Poly aPoly(a * r + p*e0);

		ciphertext->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}

	powersOfBaseInit = BigInteger(1);

	for (usint i = 0; i < l; i++) {

		Poly r(tug, elementParams, Format::EVALUATION); //r is the random noise

		Poly e0(tug, elementParams, Format::EVALUATION);

		Poly e1(tug, elementParams, Format::EVALUATION);

		Poly bPoly(b * r + p*e1);

		Poly aPoly(a * r + p*e0 + m * (powersOfBaseInit << (base * i)));

		ciphertext->SetElementAtIndex(i + l, std::move(bPoly), std::move(aPoly));
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

	std::cout<< "Ciphertext size is "<< ciphertext->GetElements().size()<<'\n';

	/*for(usint i=1;i<ciphertext->GetElements().size();i++){
		b = c[i].GetB()-s*c[i].GetA();
		b.SwitchFormat();
		std::cout<< b<<'\n';
	}*/


	return result;
}
RGSWCiphertext RGSWOps::Add(const RGSWCiphertext& a, const RGSWCiphertext& b) {
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Poly>>(a.GetCryptoParameters());
	RGSWCiphertext result(cryptoParamsBGV);
	return result;
}

std::shared_ptr<RGSWCiphertext> RGSWOps::ScalarMultiply(const BigInteger &a,const std::shared_ptr<RGSWCiphertext> ciphertext) {
	const auto cryptoParams = ciphertext->GetCryptoParameters();
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Poly>>(cryptoParams);
	auto result = make_shared<RGSWCiphertext>(cryptoParamsBGV);

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

std::shared_ptr<RGSWCiphertext> RingMultiply(const Poly& a, const std::shared_ptr<RGSWCiphertext> cipher) {

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Poly>>(cipher->GetCryptoParameters());
	shared_ptr<RGSWCiphertext> result = std::make_shared<RGSWCiphertext>(cryptoParamsBGV);

	return result;
}


std::shared_ptr<RGSWCiphertext> RGSWOps::Multiply(const std::shared_ptr<RGSWCiphertext> a, const std::shared_ptr<RGSWCiphertext> b) {

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Poly>>(a->GetCryptoParameters());
	shared_ptr<RGSWCiphertext> result = std::make_shared<RGSWCiphertext>(cryptoParamsBGV);

	usint relinWindow = cryptoParamsBGV->GetRelinWindow();
	usint N = a->GetElements().size(); //N = 2l
	usint l = N>>1;

	for (usint i = 0; i < N; i++) {
		const auto& aPoly = a->GetElements().at(i).GetA();
		const auto& bPoly = a->GetElements().at(i).GetB();
		const auto& aPolyDigits = aPoly.BaseDecompose(relinWindow);
		const auto& bPolyDigits = bPoly.BaseDecompose(relinWindow);

		auto bResultPoly(bPolyDigits[0] * b->GetElements().at(0).GetB());
		auto aResultPoly(bPolyDigits[0] * b->GetElements().at(0).GetA());

		for (usint j = 1; j < l; j++) {
			bResultPoly+= bPolyDigits[j] * b->GetElements().at(j).GetB();
			aResultPoly+= bPolyDigits[j] * b->GetElements().at(j).GetA();

		}
		for (usint j = l; j < N; j++) {
			bResultPoly+= aPolyDigits[j-l] * b->GetElements().at(j).GetB();
			aResultPoly+= aPolyDigits[j-l] * b->GetElements().at(j).GetA();
		}
		result->SetElementAtIndex(i,std::move(bResultPoly),std::move(aResultPoly));
	}

	return result;
}

}
#endif
