#ifndef LBCRYPTO_CRYPTO_ISTANDARDLWEOPS_C
#define LBCRYPTO_CRYPTO_ISTANDARDLWEOPS_C

#include "ISLWE.h"

namespace lbcrypto{

Poly GetEncoding1(const shared_ptr<LPCryptoParameters<Poly>> cryptoParams,usint message, usint q){
	//message is in Zq

	const auto &elemParams = cryptoParams->GetElementParams();
	const auto& modulus = elemParams->GetModulus();
	usint p = cryptoParams->GetPlaintextModulus();
	usint m = elemParams->GetCyclotomicOrder();
	usint N = elemParams->GetRingDimension(); //ring dimension

	BigVector vec(N, modulus);

	usint idx = (m/q)*message; //idx is between 0 to 2N-1

	if(idx>N-1){
		idx = idx%N;
		vec[idx] = BigInteger(p-1);
	}
	else{
		vec[idx] = BigInteger(1);
	}

	Poly result(cryptoParams->GetElementParams(),COEFFICIENT,true);
	result.SetValues(vec, COEFFICIENT);

	return std::move(result);
}

Poly GetEncoding1(const shared_ptr<LPCryptoParameters<Poly>> cryptoParams,NativeInteger message, NativeInteger q){
	//message is in Zq
	return GetEncoding1(cryptoParams, message.ConvertToInt(), q.ConvertToInt());
}

NativeInteger Sum1(const NativeVector &vec){
	NativeInteger ans(0);
	for(usint i=0;i<vec.GetLength();i++){
		ans+= vec[i];
		ans = ans.Mod(vec.GetModulus());
	}
	return ans.Mod(vec.GetModulus());
}

ILWEKeyPair ISLWEOps::KeyGen(const shared_ptr<ILWEParams> &param) {
	ILWEKeyPair kp(param);

	usint dim = param->GetDimension();
	auto modulus = param->GetModulus();
	auto p = param->GetPlaintextModulus();
	auto s = param->GetDiscreteGaussianGenerator().GenerateVector(dim,modulus);
	auto a = param->GetDiscreteUniformGenerator().GenerateVector(dim);
	auto e = param->GetDiscreteGaussianGenerator().GenerateInteger(modulus);
	//make e positive
	if(e>(modulus>>1)){
		e = modulus.ModSub(e,modulus);
	}

	kp.secretkey->SetSKElement(s);
	kp.publickey->SetA(a);

	NativeInteger b(0);

	b = Sum1(a*s)+ p*e;
	b = b.Mod(a.GetModulus());
	kp.publickey->SetB(b);

	return kp;
}

shared_ptr<ILWECiphertext> ISLWEOps::Encrypt(const ILWEPublicKey &pk, usint m) {

	auto result = make_shared<ILWECiphertext>(pk.GetLWEParams());

	auto q = pk.GetLWEParams()->GetModulus();

	NativeInteger val(m);

	val += pk.GetPKElement()->GetB();// val = a.s + p*e + m

	val = val.Mod(q); //reduce mod q

	result->SetA(pk.GetPKElement()->GetA());

	result->SetB(val);

	return result;
}

usint ISLWEOps::Decrypt(const shared_ptr<ILWECiphertext> cipher,const ILWESecretKey &sk) {
	auto a = cipher->GetA();
	auto b = cipher->GetB();
	auto s = sk.GetSKElement();
	auto p = sk.GetLWEParams()->GetPlaintextModulus();
	auto q = sk.GetLWEParams()->GetModulus();

	auto val = Sum1(a * s);
	val = b.ModSub(val, q); //val = b-a*s
	auto halfQ = q >> 1;
	if (val > halfQ) {
		val = val.ModSub(q, p);
	} else {
		val = val.Mod(p);
	}

	return val.ConvertToInt();
}

void ISLWEOps::KeySwitchGen(const ILWESecretKey &sk) {

}

std::vector<std::vector<std::vector<std::shared_ptr<RGSWCiphertext>>>> ISLWEOps::BootstrappingKeyGen(const ILWESecretKey &sk,usint rWindow,const RGSWPublicKey &pk){
	std::vector<std::vector<std::vector<std::shared_ptr<RGSWCiphertext>>>> result;

	const auto cryptoParams = pk.GetCryptoParameters();

	auto islweParams = sk.GetLWEParams();
	usint lweDim = islweParams->GetDimension();
	usint base = 1<<rWindow;
	auto q = islweParams->GetModulus();
	const auto &s = sk.GetSKElement();
	usint l = q.GetMSB();

	l = std::ceil((double)l/(double)rWindow);

	std::cout<<"base is "<<base<<'\n';
	std::cout<<"lweDim is "<<lweDim<<'\n';
	std::cout<<"l is "<<l<<'\n';

	for (usint i = 0; i < base; i++) {
		result.push_back(std::vector<std::vector<std::shared_ptr<RGSWCiphertext>>>());
		std::cout<<"running i= "<<i<<'\n';
		for (usint j = 0; j < lweDim; j++) {
			result[i].push_back(std::vector<std::shared_ptr<RGSWCiphertext>>());
			std::cout<<"running j= "<<j<<'\n';
			for (usint k = 0; k < l; k++) {
				auto val = (NativeInteger(i)*s[j]).Mod(q);
				val = (val*NativeInteger(base<<k)).Mod(q);
				auto encoding = GetEncoding1(cryptoParams,val,q);
				auto cipher = RGSWOps::Encrypt(pk, encoding);
				result[i][j].push_back(cipher);
				std::cout<<"finished k= "<<k<<'\n';
			}
		}
	}

	return result;
}


}


#endif
