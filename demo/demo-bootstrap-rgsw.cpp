#include "palisade.h"
#include "../src/ILWEOps.h"
#include "../src/integerlwedefs.h"
#include "cryptocontext.h"
#include "../src/ringgsw.h"
#include "../src/RingGSWOPS.h"
#include <numeric>
#include <functional>

using namespace lbcrypto;
using namespace std;

Poly GetEncoding(const shared_ptr<LPCryptoParameters<Poly>> cryptoParams,usint message, usint q);
Poly GetEncoding(const shared_ptr<LPCryptoParameters<Poly>> cryptoParams,NativeInteger message, NativeInteger q);
const shared_ptr<LPCryptoParameters<Poly>> GetRGSWCryptoParams();
void runBootstrappingExperiment(usint m1, usint m2);
vector<shared_ptr<RGSWCiphertext>> GenerateBootstrappingKey(const NativeVector &nv, const shared_ptr<LPCryptoParameters<Poly>> cpr, const shared_ptr<RGSWPublicKey> pk);
void runSingleCiphertextBootstrappingExperiment(usint m);
void runConvolutionTest();
void runConvolutionTestofTestingVector();


int main(int argc, char *argv[]){

	//runBootstrappingExperiment(1,0);
	//runConvolutionTest();
	runConvolutionTestofTestingVector();
	return 0;

}

Poly GetEncoding(const shared_ptr<LPCryptoParameters<Poly>> cryptoParams,usint message, usint q){
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

Poly GetEncoding(const shared_ptr<LPCryptoParameters<Poly>> cryptoParams,NativeInteger message, NativeInteger q){
	//message is in Zq
	return GetEncoding(cryptoParams, message.ConvertToInt(), q.ConvertToInt());
}


void runBootstrappingExperiment(usint m1, usint m2){
	NativeInteger q(512);
	NativeInteger p(5);
	usint dim = 5;

	auto dgg = make_shared<NativePoly::DggType>(2.0);
	auto dug = make_shared<NativePoly::DugType>();
	dug->SetModulus(q);

	shared_ptr<ILWEParams> params = make_shared<ILWEParams>(p,q,dim);

	params->SetDiscreteUniformGenerator(dug);
	params->SetDiscreteGaussianGenerator(dgg);

	auto kp = ILWEOps::KeyGen(params);

	cout << "operand 1 is: " << m1 << '\n';
	cout << "operand 2 is: " << m2 << '\n';

	cout << "Encrypting Operand 1\n";
	auto cipher1 = ILWEOps::Encrypt(*kp.publickey, m1);

	cout << "Encrypting Operand 2\n";
	auto cipher2 = ILWEOps::Encrypt(*kp.publickey, m2);

	cout << "Running HomNand Operation\n";
	auto cipherNAND = ILWEOps::EvalNand(cipher1,cipher2);


	auto cryptoParamRGSW = GetRGSWCryptoParams();

	// Initialize the public key containers.
	RGSWKeyPair kpRGSW = RGSWOps::KeyGen(cryptoParamRGSW);


	auto as(cipherNAND->GetA()*kp.secretkey->GetSKElement());
	auto b = cipherNAND->GetB();
	b += q/4;
	b = b.Mod(q);

	//bCipher is the ACCUMULATOR
	auto bEncoding = GetEncoding(cryptoParamRGSW,b,q);
	auto bCipher = RGSWOps::Encrypt(*kpRGSW.publicKey, bEncoding);

	std::cout<<"starting generation of bootKey\n";
	auto bootKey = GenerateBootstrappingKey(as, cryptoParamRGSW, kpRGSW.publicKey);
	std::cout<<"finished generation of bootKey\n";

	for (auto i : bootKey) {
		bCipher = RGSWOps::Multiply(bCipher, i);
		/*auto result = RGSWOps::Decrypt(bCipher, kpRGSW.secretKey );
		cout << result << '\n'<<'\n';*/
	}

	auto result = RGSWOps::Decrypt(bCipher, kpRGSW.secretKey);

	cout << result << '\n'<<'\n';

	BigInteger sum(0);
	for(usint i=0;i<result.GetLength();i++){
		sum+= result[i];
		sum = sum.Mod(BigInteger(p));
	}

	cout << "The bit refreshed/bootstarpped  is " << ((BigInteger(1).ModSub(sum,BigInteger(p)))>>1) <<'\n';

}

const shared_ptr<LPCryptoParameters<Poly>> GetRGSWCryptoParams(){
	usint m = 512;
	usint p = 5;
	BigInteger modulusP(p);
	BigInteger modulusQ("1073750017");
	BigInteger rootOfUnity("1063435359");

	float stdDev = 4;
	float assm = 9;//assuranceMeasure
	float sL = 1.006;//securityLevel
	usint relinWindow = 8;
	auto ep = make_shared < ILParams > (m, modulusQ, rootOfUnity);

	auto params = make_shared <LPCryptoParametersBGV<Poly>> (ep, p, stdDev, assm, sL, relinWindow, RLWE);

	return params;
}

vector<shared_ptr<RGSWCiphertext>> GenerateBootstrappingKey(const NativeVector &nv, const shared_ptr<LPCryptoParameters<Poly>> cpr, const shared_ptr<RGSWPublicKey> pk){
	vector<shared_ptr<RGSWCiphertext>> result;

	NativeVector as(nv);
	auto q = as.GetModulus();
	//Negate as vector
	for (usint i = 0; i < as.GetLength(); i++) {
		as[i] = q.ModSub(as[i], q);
		auto encoding = GetEncoding(cpr, as[i], q);
		auto cipher = RGSWOps::Encrypt(*pk, encoding);
		result.push_back(cipher);
	}

	return std::move(result);
}

void runSingleCiphertextBootstrappingExperiment(usint m){
	//m shouuld be in Zp
	NativeInteger q(512);
	NativeInteger p(5);
	usint dim = 5;

	auto dgg = make_shared<NativePoly::DggType>(2.0);
	auto dug = make_shared<NativePoly::DugType>();
	dug->SetModulus(q);

	shared_ptr<ILWEParams> params = make_shared<ILWEParams>(p,q,dim);

	params->SetDiscreteUniformGenerator(dug);
	params->SetDiscreteGaussianGenerator(dgg);

	auto kp = ILWEOps::KeyGen(params);

}

void runConvolutionTest(){
	usint m = 64;
	usint p = 5;
	BigInteger modulusP(p);
	BigInteger modulusQ("1073741953");
	BigInteger rootOfUnity("1062392951");

	float stdDev = 4;
	float assm = 9;//assuranceMeasure
	float sL = 1.006;//securityLevel
	usint relinWindow = 4;
	auto ep = make_shared < ILParams > (m, modulusQ, rootOfUnity);

	auto params = make_shared <LPCryptoParametersBGV<Poly>> (ep, p, stdDev, assm, sL, relinWindow, RLWE);

	RGSWKeyPair kpRGSW = RGSWOps::KeyGen(params);

	usint q = 16;

	usint b1 = 3;
	usint b2 = 4;

	auto b1Encoding = GetEncoding(params, b1, q);
	cout<< b1Encoding<<'\n';
	auto b2Encoding = GetEncoding(params, b2, q);
	cout<< b2Encoding<<'\n';

	auto b1Cipher = RGSWOps::Encrypt(*kpRGSW.publicKey, b1Encoding);
	auto b2Cipher = RGSWOps::Encrypt(*kpRGSW.publicKey, b2Encoding);

	auto bAddCipher = RGSWOps::Multiply(b1Cipher, b2Cipher);

	auto result = RGSWOps::Decrypt(bAddCipher, kpRGSW.secretKey);

	cout << result << '\n'<<'\n';
}

void runConvolutionTestofTestingVector(){
	usint m = 16;
	usint p = 5;
	BigInteger modulusP(p);
	BigInteger modulusQ("1073741857");
	BigInteger rootOfUnity("980524046");

	float stdDev = 4;
	float assm = 9;//assuranceMeasure
	float sL = 1.006;//securityLevel
	usint relinWindow = 4;
	auto ep = make_shared < ILParams > (m, modulusQ, rootOfUnity);

	auto params = make_shared <LPCryptoParametersBGV<Poly>> (ep, p, stdDev, assm, sL, relinWindow, RLWE);

	RGSWKeyPair kpRGSW = RGSWOps::KeyGen(params);

	usint q = 16;

	usint b1 = 10;
	usint b2 = 4;

	auto b1Encoding = GetEncoding(params, b1, q);
	cout<< b1Encoding<<'\n';
	auto b2Encoding = GetEncoding(params, b2, q);
	auto bSumEncoding = GetEncoding(params, b2, q);
	b2Encoding = {1,1,1,1,1,1,1,1};
	bSumEncoding = {1,p-1,p-1,p-1,p-1,p-1,p-1,p-1};
	cout << b2Encoding << '\n';

	auto b1Cipher = RGSWOps::Encrypt(*kpRGSW.publicKey, b1Encoding);
	auto b2Cipher = RGSWOps::Encrypt(*kpRGSW.publicKey, b2Encoding);
	auto bSumCipher = RGSWOps::Encrypt(*kpRGSW.publicKey, bSumEncoding);

	auto bAddCipher = RGSWOps::Multiply(b1Cipher, b2Cipher);
	bAddCipher = RGSWOps::Multiply(bSumCipher, bAddCipher);

	auto result = RGSWOps::Decrypt(bAddCipher, kpRGSW.secretKey);

	cout << result << '\n'<<'\n';
}
