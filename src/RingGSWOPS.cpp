#ifndef LBCRYPTO_CRYPTO_RGSWOPS_C
#define LBCRYPTO_CRYPTO_RGSWOPS_C

#include "RingGSWOPS.h"
#include "ringgsw.cpp"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

template <class Element>
RGSWOps<Element>::RGSWOps(){

}

template <class Element>
RGSWKeyPair<Element> RGSWOps<Element>::KeyGen(const shared_ptr<LPCryptoParameters<Element>> cryptoParams) {

	const shared_ptr<LPCryptoParametersBGV<Element>> cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(cryptoParams);

	RGSWKeyPair<Element> kp(cryptoParams);

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsBGV->GetElementParams();

	const auto p = cryptoParamsBGV->GetPlaintextModulus();

	const typename Element::DggType &dgg = cryptoParamsBGV->GetDiscreteGaussianGenerator();

	typename Element::DugType dug;

	//Generate the secret key
	Element s(dgg, elementParams, Format::COEFFICIENT);

	s.SwitchFormat();

	const typename Element::TugType tug;

	//Generate the uniformly random element "a" of the public key
	Element a(dug, elementParams, Format::EVALUATION);

	Element e(tug, elementParams, Format::EVALUATION);

	Element b = a*s + p*e;

	kp.publicKey->SetPublicElements(std::move(a),std::move(b));

	kp.secretKey->SetSecretKey(std::move(s));

	return kp;

}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::Encrypt(const RGSWPublicKey<Element> &pk, Element &m) {

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(pk.GetCryptoParameters());

	shared_ptr<RGSWCiphertext<Element>> ciphertext = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsBGV->GetElementParams();

	const auto p = cryptoParamsBGV->GetPlaintextModulus();

	const typename Element::TugType tug;

	m.SwitchFormat();

	usint base = cryptoParamsBGV->GetRelinWindow();

	usint l = elementParams->GetModulus().GetMSB();

	l = std::ceil((double)l/(double)base);

	typename Element::Integer powersOfBaseInit(1);//2^r

	const Element &a = pk.GetPublicElements().GetA();
	const Element &b = pk.GetPublicElements().GetB();

	for (usint i = 0; i < l; i++) {

		Element r(tug, elementParams, Format::EVALUATION); //r is the random noise

		//Element e0(tug, elementParams, Format::EVALUATION);

		//Element e1(tug, elementParams, Format::EVALUATION);

		//Element bPoly(b * r + p * e1 + m * (powersOfBaseInit << (base * i)));

		//Element aPoly(a * r + p * e0);

		Element bPoly(b * r  + m * (powersOfBaseInit << (base * i)));

		Element aPoly(a * r );


		ciphertext->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}

	powersOfBaseInit = typename Element::Integer(1);

	for (usint i = 0; i < l; i++) {

		Element r(tug, elementParams, Format::EVALUATION); //r is the random noise

		Element e0(tug, elementParams, Format::EVALUATION);

		Element e1(tug, elementParams, Format::EVALUATION);

		Element bPoly(b * r + p * e1);

		Element aPoly(a * r + p * e0 + m * (powersOfBaseInit << (base * i)));

		ciphertext->SetElementAtIndex(i + l, std::move(bPoly), std::move(aPoly));
	}

	return ciphertext;
}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::ClearEncrypt(const RGSWPublicKey<Element> &pk, Element &m){

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(pk.GetCryptoParameters());

	shared_ptr<RGSWCiphertext<Element>> cleartext = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	const shared_ptr<typename Element::Params> elementParams = cryptoParamsBGV->GetElementParams();

	m.SwitchFormat();

	usint base = cryptoParamsBGV->GetRelinWindow();

	usint l = elementParams->GetModulus().GetMSB();

	l = std::ceil((double)l/(double)base);

	typename Element::Integer powersOfBaseInit(1);//2^r

	for (usint i = 0; i < l; i++) {

		Element bPoly(m * (powersOfBaseInit << (base * i)));

		Element aPoly(elementParams, EVALUATION, true);

		cleartext->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}

	powersOfBaseInit = typename Element::Integer(1);

	for (usint i = 0; i < l; i++) {

		Element bPoly(elementParams, EVALUATION, true);

		Element aPoly(m * (powersOfBaseInit << (base * i)));

		cleartext->SetElementAtIndex(i + l, std::move(bPoly), std::move(aPoly));
	}

	return cleartext;
}

template <class Element>
Element RGSWOps<Element>::Decrypt(const std::shared_ptr<RGSWCiphertext<Element>> ciphertext,const std::shared_ptr<RGSWSecretKey<Element>> sk) {
	Element result;
	//std::vector<Poly> toShowAsOutput;

	const auto cryptoParams = sk->GetCryptoParameters();
	const auto p = cryptoParams->GetPlaintextModulus();
	const auto &c = ciphertext->GetElements();
	const auto &s = sk->GetSecretKey();

	Element b = c[0].GetB() - s * c[0].GetA();

	auto bCheck = b.CRTInterpolate();

	b.SwitchFormat();

	//result = b.Mod(p);
	auto resultCheck = bCheck.Mod(p);

	std::cout << resultCheck << std::endl;
	//std::cout<< "Ciphertext size is "<< ciphertext->GetElements().size()<<'\n';

	/*for(usint i=1;i<ciphertext->GetElements().size();i++){
		b = c[i].GetB()-s*c[i].GetA();
		b.SwitchFormat();
		std::cout<< b<<'\n';
	}*/


	return result;
}

template <class Element>
RGSWCiphertext<Element> RGSWOps<Element>::Add(const RGSWCiphertext<Element>& a, const RGSWCiphertext<Element>& b) {
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(a.GetCryptoParameters());
	RGSWCiphertext<Element> result(cryptoParamsBGV);
	return result;
}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::ScalarMultiply(const BigInteger &a,const std::shared_ptr<RGSWCiphertext<Element>> ciphertext) {
	const auto cryptoParams = ciphertext->GetCryptoParameters();
	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(cryptoParams);
	auto result = make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	auto logQ = ciphertext->GetElements().size();
	auto r = cryptoParams->GetRelinWindow();
	auto base = 1<<r;

	for(usint i=0;i<logQ;i++){
		BigInteger scalarValue = a<<(i*r);
		usint digit = scalarValue.GetDigitAtIndexForBase(1,base);
		Element a = typename Element::Integer(digit)*ciphertext->GetElements().at(0).GetA();
		Element b = typename Element::Integer(digit)*ciphertext->GetElements().at(0).GetB();
		for(usint j=1;j<logQ;j++){
			digit = scalarValue.GetDigitAtIndexForBase(j+1,base);
			a+= typename Element::Integer(digit)*ciphertext->GetElements().at(j).GetA();
			b+= typename Element::Integer(digit)*ciphertext->GetElements().at(j).GetB();
		}
		result->SetElementAtIndex(i,std::move(a),std::move(b));
	}
	return result;
}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::RingMultiply(const Element& a, const std::shared_ptr<RGSWCiphertext<Element>> cipher) {

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(cipher->GetCryptoParameters());
	shared_ptr<RGSWCiphertext<Element>> result = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

	return result;
}

template <class Element>
std::shared_ptr<RGSWCiphertext<Element>> RGSWOps<Element>::Multiply(const std::shared_ptr<RGSWCiphertext<Element>> a, const std::shared_ptr<RGSWCiphertext<Element>> b) {

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Element>>(a->GetCryptoParameters());
	shared_ptr<RGSWCiphertext<Element>> result = std::make_shared<RGSWCiphertext<Element>>(cryptoParamsBGV);

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

template <>
inline std::shared_ptr<RGSWCiphertext<CRTPoly>> RGSWOps<CRTPoly>::Encrypt(const RGSWPublicKey<CRTPoly> &pk, CRTPoly &m){

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<CRTPoly>>(pk.GetCryptoParameters());

	shared_ptr<RGSWCiphertext<CRTPoly>> ciphertext = std::make_shared<RGSWCiphertext<CRTPoly>>(cryptoParamsBGV);

	const auto elementParams = cryptoParamsBGV->GetElementParams();

	const auto p = cryptoParamsBGV->GetPlaintextModulus();

	const CRTPoly::TugType tug;

	m.SwitchFormat();

	usint base = cryptoParamsBGV->GetRelinWindow();

	usint l = elementParams->GetParams().back()->GetModulus().GetMSB();

	l = std::ceil((double) l / (double) base);

	CRTPoly::Integer powersOfBaseInit(1); //2^r

	const CRTPoly &a = pk.GetPublicElements().GetA();
	const CRTPoly &b = pk.GetPublicElements().GetB();

	for (usint i = 0; i < l; i++) {

		CRTPoly r(tug, elementParams, Format::EVALUATION); //r is the random noise

		CRTPoly e0(tug, elementParams, Format::EVALUATION);

		CRTPoly e1(tug, elementParams, Format::EVALUATION);

		CRTPoly bPoly(b * r + p * e1 + m * (powersOfBaseInit << (base * i)));

		CRTPoly aPoly(a * r + p * e0);

		ciphertext->SetElementAtIndex(i, std::move(bPoly), std::move(aPoly));
	}

	powersOfBaseInit = CRTPoly::Integer(1);

	for (usint i = 0; i < l; i++) {

		CRTPoly r(tug, elementParams, Format::EVALUATION); //r is the random noise

		CRTPoly e0(tug, elementParams, Format::EVALUATION);

		CRTPoly e1(tug, elementParams, Format::EVALUATION);

		CRTPoly bPoly(b * r + p * e1);

		CRTPoly aPoly(a * r + p * e0 + m * (powersOfBaseInit << (base * i)));

		ciphertext->SetElementAtIndex(i + l, std::move(bPoly), std::move(aPoly));
	}

	return ciphertext;
}


template <>
inline std::shared_ptr<RGSWCiphertext<CRTPoly>> RGSWOps<CRTPoly>::Multiply(const std::shared_ptr<RGSWCiphertext<CRTPoly>> cipherA, const std::shared_ptr<RGSWCiphertext<CRTPoly>> cipherB) {

	if (cipherA->GetElements().size() != cipherB->GetElements().size()) {
		throw std::runtime_error("unequal ciphertext size provided");
	}

	const auto cryptoParamsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<CRTPoly>>(cipherA->GetCryptoParameters());
	shared_ptr<RGSWCiphertext<CRTPoly>> result = std::make_shared<RGSWCiphertext<CRTPoly>>(cryptoParamsBGV);

	usint relinWindow = cryptoParamsBGV->GetRelinWindow();
	auto crtParam = cryptoParamsBGV->GetElementParams();

	usint l = cipherA->GetElements().size()>>1;

	usint nTowers = cipherA->GetElements().at(0).GetA().GetParams()->GetParams().size(); //crt size

	usint nBitsInQPrime = cipherA->GetElements().at(0).GetA().GetElementAtIndex(nTowers-2).GetModulus().GetMSB();//QPrime is the second largest modulus in crt
	usint lPrime = std::ceil((double) nBitsInQPrime / (double) relinWindow); //relinearization window of largest modulus after modulus reduction
	usint NPrime = lPrime << 1;

	//initialize the result ciphertext
	for (usint rowIdx = 0; rowIdx < NPrime; rowIdx++) {
		CRTPoly aEmpty(crtParam, EVALUATION, true);
		CRTPoly bEmpty(crtParam, EVALUATION, true);
		result->SetElementAtIndex(rowIdx, std::move(bEmpty), std::move(aEmpty));
	}

	for (usint t = 0; t < nTowers; t++) {
		usint nBitsInTowerMod = cryptoParamsBGV->GetElementParams()->GetParams()[t]->GetModulus().GetMSB();
		usint lTower = std::ceil((double) nBitsInTowerMod / (double) relinWindow); ///relinearization window of current tower modulus

		for (usint rowIdx = 0; rowIdx < lPrime; rowIdx++) {
			const auto& aPoly = cipherA->GetElements().at(rowIdx).GetA().GetElementAtIndex(t);
			const auto& bPoly = cipherA->GetElements().at(rowIdx).GetB().GetElementAtIndex(t);
			const auto& aPolyDigits = aPoly.BaseDecompose(relinWindow);
			const auto& bPolyDigits = bPoly.BaseDecompose(relinWindow);

			auto bResultPoly(bPolyDigits[0] * cipherB->GetElements().at(0).GetB().GetElementAtIndex(t));
			auto aResultPoly(bPolyDigits[0] * cipherB->GetElements().at(0).GetA().GetElementAtIndex(t));

			for (usint j = 1; j < lTower; j++) {
				bResultPoly+= bPolyDigits[j] * cipherB->GetElements().at(j).GetB().GetElementAtIndex(t);
				aResultPoly+= bPolyDigits[j] * cipherB->GetElements().at(j).GetA().GetElementAtIndex(t);
			}

			for (usint j = l; j < (l + lTower); j++) {
				bResultPoly+= aPolyDigits[j-l] * cipherB->GetElements().at(j).GetB().GetElementAtIndex(t);
				aResultPoly+= aPolyDigits[j-l] * cipherB->GetElements().at(j).GetA().GetElementAtIndex(t);
			}

			result->SetElementAtIndexForTower(rowIdx, t, std::move(bResultPoly), std::move(aResultPoly));

		}

		for (usint rowIdx = l; rowIdx < (l+lPrime); rowIdx++) {
			const auto& aPoly =	cipherA->GetElements().at(rowIdx).GetA().GetElementAtIndex(t);
			const auto& bPoly = cipherA->GetElements().at(rowIdx).GetB().GetElementAtIndex(t);
			const auto& aPolyDigits = aPoly.BaseDecompose(relinWindow);
			const auto& bPolyDigits = bPoly.BaseDecompose(relinWindow);

			auto bResultPoly(bPolyDigits[0] * cipherB->GetElements().at(0).GetB().GetElementAtIndex(t));
			auto aResultPoly(bPolyDigits[0]	* cipherB->GetElements().at(0).GetA().GetElementAtIndex(t));

			for (usint j = 1; j < lTower; j++) {
				bResultPoly += bPolyDigits[j] * cipherB->GetElements().at(j).GetB().GetElementAtIndex(t);
				aResultPoly += bPolyDigits[j] * cipherB->GetElements().at(j).GetA().GetElementAtIndex(t);
			}

			for (usint j = l; j < (l + lTower); j++) {
				bResultPoly += aPolyDigits[j - l] * cipherB->GetElements().at(j).GetB().GetElementAtIndex(t);
				aResultPoly += aPolyDigits[j - l] * cipherB->GetElements().at(j).GetA().GetElementAtIndex(t);
			}

			result->SetElementAtIndexForTower((rowIdx - l + lPrime), t, std::move(bResultPoly), std::move(aResultPoly));

		}
	}

	result->ModReduce();

	return result;

}


}
#endif
