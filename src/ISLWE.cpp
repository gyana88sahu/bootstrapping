#ifndef LBCRYPTO_CRYPTO_ISTANDARDLWEOPS_C
#define LBCRYPTO_CRYPTO_ISTANDARDLWEOPS_C

#include "ISLWE.h"

namespace lbcrypto{

NativeInteger Sum(const NativeVector &vec){
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

	kp.secretkey->SetSKElement(s);
	kp.publickey->SetA(a);

	NativeInteger b(0);

	b = Sum(a*s)+ p*e;
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

	auto val = Sum(a * s);
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


}


#endif
