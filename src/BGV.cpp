#ifndef SRC_BGV_CPP
#define SRC_BGV_CPP

#include "BGV.h"

namespace lbcrypto {

BGVScheme::BGVScheme() {
}

LPKeyPair<Poly> BGVScheme::KeyGen(CryptoContext<Poly> cc){
	LPKeyPair<Poly>	kp(new LPPublicKeyImpl<Poly>(cc), new LPPrivateKeyImpl<Poly>(cc));

	const shared_ptr<LPCryptoParametersBGV<Poly>> cryptoParams = std::static_pointer_cast<LPCryptoParametersBGV<Poly>>(cc->GetCryptoParameters());

	const shared_ptr<typename Poly::Params> elementParams = cryptoParams->GetElementParams();

	const auto p = cryptoParams->GetPlaintextModulus();

	const typename Poly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	typename Poly::DugType dug;

	typename Poly::TugType tug;

	//Generate the element "a" of the public key
	Poly a(dug, elementParams, Format::EVALUATION);

	//Generate the secret key
	Poly s;

	//Done in two steps not to use a random polynomial from a pre-computed pool
	//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParams->GetMode() == RLWE) {
		s = Poly(dgg, elementParams, Format::COEFFICIENT);
	}
	else {
		s = Poly(tug, elementParams, Format::COEFFICIENT);
	}
	s.SwitchFormat();

	//public key is generated and set
	//privateKey->MakePublicKey(a, publicKey);
	Poly e(dgg, elementParams, Format::COEFFICIENT);
	e.SwitchFormat();

	Poly b = a*s + p*e;

	kp.secretKey->SetPrivateElement(std::move(s));

	kp.publicKey->SetPublicElementAtIndex(0, std::move(a));

	kp.publicKey->SetPublicElementAtIndex(1, std::move(b));

	return kp;
}

Ciphertext<Poly> BGVScheme::Encrypt(const LPPublicKey<Poly> publicKey, Poly &ptxt) const{

	const shared_ptr<LPCryptoParametersBGV<Poly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBGV<Poly>>(publicKey->GetCryptoParameters());

	Ciphertext<Poly> ciphertext(new CiphertextImpl<Poly>(publicKey));

	const shared_ptr<typename Poly::Params> elementParams = cryptoParams->GetElementParams();
	const auto p = cryptoParams->GetPlaintextModulus();
	const typename Poly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	typename Poly::TugType tug;

	ptxt.SwitchFormat();

	std::vector<Poly> cVector;

	const Poly &a = publicKey->GetPublicElements().at(0);
	const Poly &b = publicKey->GetPublicElements().at(1);

	Poly v;

	//Supports both discrete Gaussian (RLWE) and ternary uniform distribution (OPTIMIZED) cases
	if (cryptoParams->GetMode() == RLWE)
		v = Poly(dgg, elementParams, Format::EVALUATION);
	else
		v = Poly(tug, elementParams, Format::EVALUATION);

	Poly e0(dgg, elementParams, Format::EVALUATION);
	Poly e1(dgg, elementParams, Format::EVALUATION);

	Poly c0(b*v + p*e0 + ptxt);

	Poly c1(a*v + p*e1);

	cVector.push_back(std::move(c0));

	cVector.push_back(std::move(c1));

	ciphertext->SetElements(std::move(cVector));


	return ciphertext;
}

DecryptResult BGVScheme::Decrypt(const LPPrivateKey<Poly> privateKey,
			const Ciphertext<Poly> ciphertext,
			NativePoly *plaintext) const{

	const shared_ptr<LPCryptoParameters<Poly>> cryptoParams = privateKey->GetCryptoParameters();
	const auto p = cryptoParams->GetPlaintextModulus();
	const std::vector<Poly> &c = ciphertext->GetElements();
	const Poly &s = privateKey->GetPrivateElement();

	Poly b = c[0] - s * c[1];

	b.SwitchFormat();

	cout << b.ModByTwo() << '\n';

	*plaintext = b.DecryptionCRTInterpolate(p);

	return DecryptResult(plaintext->GetLength());

}

Ciphertext<Poly> BGVScheme::Encrypt(const LPPublicKey<Poly> publicKey, const std::vector<int64_t> &input) const{
	Poly poly = Encode(publicKey,input);
	return this->Encrypt(publicKey,poly);
}

Poly BGVScheme::Encode(const LPPublicKey<Poly> publicKey, const std::vector<int64_t> &input) const{

	const shared_ptr<LPCryptoParametersBGV<Poly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBGV<Poly>>(publicKey->GetCryptoParameters());

	const shared_ptr<typename Poly::Params> elementParams = cryptoParams->GetElementParams();
	const auto p = cryptoParams->GetPlaintextModulus();

	usint n = elementParams->GetRingDimension();

	Poly result(elementParams,COEFFICIENT);

	if(input.size()!=n){
		throw std::runtime_error("dimension mismatch\n");
	}

	BigVector values(n,elementParams->GetModulus());

	for (usint i = 0; i < n; i++) {
		if ((uint64_t) input[i] > p || input[i] < 0) {
			throw std::runtime_error("out of range \n");
		}
		values[i] = BigInteger(input[i] % p);
	}

	result.SetValues(values,COEFFICIENT);

	return std::move(result);
}



BGVScheme::~BGVScheme() {
}

std::vector<LPEvalKey<Poly>> BGVOps::multKey = std::vector<LPEvalKey<Poly>>();

void BGVOps::GenEvalMultKey(const LPPrivateKey<Poly> key){
	BGVOps::multKey.push_back(EvalMultKeyGen(key));
}

Ciphertext<Poly> BGVOps::EvalAdd(const Ciphertext<Poly> ciphertext1,
			const Ciphertext<Poly> ciphertext2) const{

	Ciphertext<Poly> newCiphertext = ciphertext1->CloneEmpty();

	const std::vector<Poly> &c1 = ciphertext1->GetElements();

	const std::vector<Poly> &c2 = ciphertext2->GetElements();

	std::vector<Poly> cNew;

	cNew.push_back(std::move(c1[0] + c2[0]));

	cNew.push_back(std::move(c1[1] + c2[1]));

	newCiphertext->SetElements(std::move(cNew));

	return newCiphertext;

}


Ciphertext<Poly> BGVOps::EvalAdd(const Ciphertext<Poly> ciphertext,
			const Plaintext plaintext) const{

	Ciphertext<Poly> newCiphertext = ciphertext->CloneEmpty();

	const std::vector<Poly> &c1 = ciphertext->GetElements();

	plaintext->GetEncodedElement<Poly>().SetFormat(EVALUATION);

	const auto& c2 = plaintext->GetEncodedElement<Poly>();

	std::vector<Poly> cNew;

	cNew.push_back(std::move(c1[0] + c2));

	cNew.push_back(std::move(c1[1]));

	newCiphertext->SetElements(std::move(cNew));

	return newCiphertext;

}

Ciphertext<Poly> BGVOps::EvalMult(const Ciphertext<Poly> ciphertext1,const Ciphertext<Poly> ciphertext2) const{
	return this->EvalMult(ciphertext1, ciphertext2, multKey[0]);
}

Ciphertext<Poly> BGVOps::EvalMultInternal(const Ciphertext<Poly> ciphertext1,const Ciphertext<Poly> ciphertext2) const{

	if (ciphertext1->GetElements()[0].GetFormat() == Format::COEFFICIENT || ciphertext2->GetElements()[0].GetFormat() == Format::COEFFICIENT) {
				throw std::runtime_error("EvalMult cannot multiply in COEFFICIENT domain.");
			}

	Ciphertext<Poly> newCiphertext = ciphertext1->CloneEmpty();

	const std::vector<Poly> &c1 = ciphertext1->GetElements();

	const std::vector<Poly> &c2 = ciphertext2->GetElements();

	std::vector<Poly> cNew;

	cNew.push_back(std::move(c1[0] * c2[0]));

	cNew.push_back(std::move(c1[0] * c2[1] + c1[1] * c2[0]));

	cNew.push_back(std::move((c1[1] * c2[1]).Negate()));

	newCiphertext->SetElements(std::move(cNew));

	return newCiphertext;
}

Ciphertext<Poly> BGVOps::EvalMultInternal(const Ciphertext<Poly> ciphertext,const Plaintext plaintext) const{

	Ciphertext<Poly> newCiphertext = ciphertext->CloneEmpty();

	const std::vector<Poly> &c1 = ciphertext->GetElements();

	plaintext->GetEncodedElement<Poly>().SetFormat(EVALUATION);
	const auto& c2 = plaintext->GetEncodedElement<Poly>();

	if (ciphertext->GetElements()[0].GetFormat() == Format::COEFFICIENT || plaintext->GetEncodedElement<Poly>().GetFormat() == Format::COEFFICIENT) {
		throw std::runtime_error("EvalMult cannot multiply in COEFFICIENT domain.");
	}

	std::vector<Poly> cNew;

	cNew.push_back(std::move(c1[0] * c2));

	cNew.push_back(std::move(c1[1] * c2));

	//cNew.push_back(std::move(0));

	newCiphertext->SetElements(std::move(cNew));

	return newCiphertext;

}

Ciphertext<Poly> BGVOps::EvalMult(const Ciphertext<Poly> ciphertext1,
	const Ciphertext<Poly> ciphertext2,
	const LPEvalKey<Poly> ek) const{

	Ciphertext<Poly> newCiphertext = this->EvalMultInternal(ciphertext1, ciphertext2);

	return this->KeySwitch(ek, newCiphertext);

}

LPEvalKey<Poly> BGVOps::KeySwitchGen(const LPPrivateKey<Poly> originalPrivateKey,
					const LPPrivateKey<Poly> newPrivateKey) const{

	const shared_ptr<LPCryptoParametersBGV<Poly>> cryptoParams = std::dynamic_pointer_cast<LPCryptoParametersBGV<Poly>>(originalPrivateKey->GetCryptoParameters());

	const shared_ptr<typename Poly::Params> originalKeyParams = cryptoParams->GetElementParams();

	auto p = cryptoParams->GetPlaintextModulus();

	LPEvalKey<Poly> keySwitchHintRelin(new LPEvalKeyRelinImpl<Poly>(originalPrivateKey->GetCryptoContext()));

	//Getting a reference to the polynomials of new private key.
	const Poly &sNew = newPrivateKey->GetPrivateElement();

	//Getting a reference to the polynomials of original private key.
	const Poly &s = originalPrivateKey->GetPrivateElement();

	//Getting a refernce to discrete gaussian distribution generator.
	const typename Poly::DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();

	//Getting a reference to discrete uniform generator.
	typename Poly::DugType dug;

	//Relinearization window is used to calculate the base exponent.
	usint relinWindow = cryptoParams->GetRelinWindow();

	//Pushes the powers of base exponent of original key polynomial onto evalKeyElements.
	std::vector<Poly> evalKeyElements(s.PowersOfBase(relinWindow));

	//evalKeyElementsGenerated hold the generated noise distribution.
	std::vector<Poly> evalKeyElementsGenerated;

	for (usint i = 0; i < (evalKeyElements.size()); i++)
	{
		// Generate a_i vectors
		Poly a(dug, originalKeyParams, Format::EVALUATION);

		evalKeyElementsGenerated.push_back(a); //alpha's of i

											   // Generate a_i * newSK + p * e - PowerOfBase(oldSK)
		Poly e(dgg, originalKeyParams, Format::EVALUATION);

		evalKeyElements[i] = (a*sNew + p*e) - evalKeyElements[i];

	}

	keySwitchHintRelin->SetAVector(std::move(evalKeyElementsGenerated));

	keySwitchHintRelin->SetBVector(std::move(evalKeyElements));

	return keySwitchHintRelin;
}

Ciphertext<Poly> BGVOps::KeySwitch(const LPEvalKey<Poly> keySwitchHint,
			const Ciphertext<Poly> cipherText) const{

	Ciphertext<Poly> newCiphertext = cipherText->CloneEmpty();

	const shared_ptr<LPCryptoParametersBGV<Poly>> cryptoParamsLWE = std::dynamic_pointer_cast<LPCryptoParametersBGV<Poly>>(keySwitchHint->GetCryptoParameters());

	const LPEvalKeyRelin<Poly> evalKey = std::static_pointer_cast<LPEvalKeyRelinImpl<Poly>>(keySwitchHint);

	const std::vector<Poly> &a = evalKey->GetAVector();
	const std::vector<Poly> &b = evalKey->GetBVector();

	usint relinWindow = cryptoParamsLWE->GetRelinWindow();

	const std::vector<Poly> &c = cipherText->GetElements();

	std::vector<Poly> digitsC1;
	Poly ct1;

	if (c.size() == 2) //case of PRE or automorphism
	{
		digitsC1 = c[1].BaseDecompose(relinWindow);
		ct1 = digitsC1[0] * a[0];
	}
	else //case of EvalMult
	{
		digitsC1 = c[2].BaseDecompose(relinWindow);
		ct1 = c[1] + digitsC1[0] * a[0];
	}

	Poly ct0(c[0] + digitsC1[0] * b[0]);

	//Relinearization Step.
	for (usint i = 1; i < digitsC1.size(); ++i)
	{
		ct0 += digitsC1[i] * b[i];
		ct1 += digitsC1[i] * a[i];
	}

	std::vector<Poly> ctVector;

	ctVector.push_back(std::move(ct0));

	ctVector.push_back(std::move(ct1));

	newCiphertext->SetElements(std::move(ctVector));

	return newCiphertext;

}

LPEvalKey<Poly> BGVOps::EvalMultKeyGen(const LPPrivateKey<Poly> originalPrivateKey) const{

	LPPrivateKey<Poly> originalPrivateKeySquared = LPPrivateKey<Poly>(new LPPrivateKeyImpl<Poly>(originalPrivateKey->GetCryptoContext()));

	Poly sSquare(originalPrivateKey->GetPrivateElement()*originalPrivateKey->GetPrivateElement());

	originalPrivateKeySquared->SetPrivateElement(std::move(sSquare));

	return this->KeySwitchGen(originalPrivateKeySquared, originalPrivateKey);

}


}

#endif

