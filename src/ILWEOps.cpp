#ifndef LBCRYPTO_CRYPTO_ILWEOPS_C
#define LBCRYPTO_CRYPTO_ILWEOPS_C

#include "ILWEOps.h"

namespace lbcrypto {

NativeInteger Sum(const NativeVector &vec){
	NativeInteger ans(0);
	for(usint i=0;i<vec.GetLength();i++){
		ans+= vec[i];
		ans = ans.Mod(vec.GetModulus());
	}
	return ans.Mod(vec.GetModulus());
}

ILWEKeyPair ILWEOps::KeyGen(const shared_ptr<ILWEParams> &param) {
	ILWEKeyPair kp(param);

	usint dim = param->GetDimension();
	auto modulus = param->GetModulus();
	auto s = param->GetDiscreteGaussianGenerator().GenerateVector(dim,modulus);
	auto a = param->GetDiscreteUniformGenerator().GenerateVector(dim);
	auto e = param->GetDiscreteGaussianGenerator().GenerateVector(dim,modulus);

	kp.secretkey->SetSKElement(s);
	kp.publickey->SetA(a);

	NativeInteger b(0);
	auto val = a*s+e;
	b = Sum(val);
	kp.publickey->SetB(b);

	return kp;
}

shared_ptr<ILWECiphertext> ILWEOps::Encrypt(const ILWEPublicKey &pk, usint m) {

	auto result = make_shared<ILWECiphertext>(pk.GetLWEParams());

	auto q = pk.GetLWEParams()->GetModulus();

	auto t = pk.GetLWEParams()->GetPlaintextModulus();

	auto val = (m*q).DivideAndRound(t); //round(mq/t)

	val += pk.GetPKElement()->GetB();// val = a.s + e + round(mq/t)

	val = val.Mod(q); //reduce mod q

	result->SetA(pk.GetPKElement()->GetA());

	result->SetB(val);

	return result;
}

usint ILWEOps::Decrypt(const shared_ptr<ILWECiphertext> cipher,const ILWESecretKey &sk) {
	auto a = cipher->GetA();
	auto b = cipher->GetB();
	auto s = sk.GetSKElement();
	auto t = sk.GetLWEParams()->GetPlaintextModulus();
	auto q = sk.GetLWEParams()->GetModulus();

	auto val = Sum(a*s);
	val = b.ModSub(val,q); //val = b-a*s
	val = (val*t).DivideAndRound(q);

	return val.ConvertToInt();
}

void ILWEOps::KeySwitchGen(const ILWESecretKey &sk) {

}

}
#endif /* SRC_ILWEOPS_H_ */
