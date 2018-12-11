#include "palisade.h"
#include "../src/ISLWE.cpp"
#include "cryptocontext.h"
#include "../src/gsw-impl.cpp"
#include <numeric>
#include <functional>
//#include "../src/CryptoTree.h"


using namespace lbcrypto;
using namespace std;

template <class Element>
Element GetEncoding(const shared_ptr<LPCryptoParameters<Element>> cryptoParams,usint message, usint q);

template <class Element>
Element GetEncoding(const shared_ptr<LPCryptoParameters<Element>> cryptoParams,typename Element::Integer &message,typename Element::Integer &q);

template <class Element>
const shared_ptr<LPCryptoParameters<Element>> GetRGSWCryptoParams();

void runBootstrappingExperiment(usint m1, usint m2);

template <class Element>
vector<shared_ptr<RGSWCiphertext<Element>>> GenerateBootstrappingKey(const typename Element::Vector &nv, const shared_ptr<LPCryptoParameters<Element>> cpr, const shared_ptr<RGSWPublicKey<Element>> pk);


template <class Element>
void runSingleCiphertextBootstrappingExperiment(usint m);

void runConvolutionTest();

void runConvolutionTestofTestingVector();

template <class Element>
Element GenerateAggregationVector(const shared_ptr<LPCryptoParameters<Element>> cpr);

template <class Element>
shared_ptr<ILWECiphertext> ConvertToSLWE(const std::shared_ptr<RGSWCiphertext<Element>> rgswCipher,shared_ptr<ILWEParams> params);

template <class Element>
usint CheckLWE(shared_ptr<ILWECiphertext> lweCipher, shared_ptr<RGSWSecretKey<Element>> ringSK);

//For capturing bootstrapping key size and KeySwitchHint Size
void runProposalExperimentForSize(usint n,usint r,usint q);

template <class Element>
void runProposalExperimentForBootstrappingKeySize(usint n,usint r, usint q);

template <class Element>
void runProposalExperimentForRGSWTimings();

int main(int argc, char *argv[]){

	runSingleCiphertextBootstrappingExperiment<NativePoly>(1);

	return 0;

}

template <class Element>
Element GetEncoding(const shared_ptr<LPCryptoParameters<Element>> cryptoParams,usint message, usint q){
	//message is in Zq

	const auto &elemParams = cryptoParams->GetElementParams();
	const auto& modulus = elemParams->GetModulus();
	usint p = cryptoParams->GetPlaintextModulus();
	usint m = elemParams->GetCyclotomicOrder();
	usint N = elemParams->GetRingDimension(); //ring dimension

	typename Element::Vector vec(N, modulus);

	usint idx = (m/q)*message; //idx is between 0 to 2N-1

	if(idx>N-1){
		idx = idx%N;
		vec[idx] = typename Element::Integer(p-1);
	}
	else{
		vec[idx] = typename Element::Integer(1);
	}

	Element result(elemParams, COEFFICIENT, true);
	result.SetValues(vec, COEFFICIENT);

	return std::move(result);
}

template <class Element>
Element GetEncoding(const shared_ptr<LPCryptoParameters<Element>> cryptoParams,typename Element::Integer &message, typename Element::Integer &q){
	//message is in Zq
	return GetEncoding<Element>(cryptoParams, message.ConvertToInt(), q.ConvertToInt());
}


void runBootstrappingExperiment(usint m1, usint m2){
	/*NativeInteger q(512);
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


	auto cryptoParamRGSW = GetRGSWCryptoParams<NativePoly>();

	// Initialize the public key containers.
	RGSWKeyPair<NativePoly> kpRGSW = RGSWOps<NativePoly>::KeyGen(cryptoParamRGSW);


	auto as(cipherNAND->GetA()*kp.secretkey->GetSKElement());
	auto b = cipherNAND->GetB();
	b += q/4;
	b = b.Mod(q);

	//bCipher is the ACCUMULATOR
	auto bEncoding = GetEncoding(cryptoParamRGSW,b,q);
	auto bCipher = RGSWOps<NativePoly>::Encrypt(*kpRGSW.publicKey, bEncoding);

	std::cout<<"starting generation of bootKey\n";
	auto bootKey = GenerateBootstrappingKey(as, cryptoParamRGSW, kpRGSW.publicKey);
	std::cout<<"finished generation of bootKey\n";

	for (auto i : bootKey) {
		bCipher = RGSWOps<NativePoly>::Multiply(bCipher, i);
		auto result = RGSWOps::Decrypt(bCipher, kpRGSW.secretKey );
		cout << result << '\n'<<'\n';
	}

	auto result = RGSWOps<NativePoly>::Decrypt(bCipher, kpRGSW.secretKey);

	cout << result << '\n'<<'\n';

	NativePoly::Integer sum(0);
	for(usint i=0;i<result.GetLength();i++){
		sum+= result[i];
		sum = sum.Mod(NativePoly::Integer(p));
	}

	cout << "The bit refreshed/bootstarpped  is " << ((NativePoly::Integer(1).ModSub(sum,NativePoly::Integer(p)))>>1) <<'\n';
*/
}

template <class Element>
const shared_ptr<LPCryptoParameters<Element>> GetRGSWCryptoParams(){
	usint m = 512;
	usint p = 5;
	typename Element::Integer modulusP(p);
	typename Element::Integer modulusQ("1125899906844161");
	typename Element::Integer rootOfUnity("1123897446934361");

	float stdDev = 4;
	float assm = 9;//assuranceMeasure
	float sL = 1.006;//securityLevel
	usint relinWindow = 16;
	auto ep = make_shared < typename Element::Params > (m, modulusQ, rootOfUnity);

	auto params = make_shared <LPCryptoParametersBGV<Element>> (ep, p, stdDev, assm, sL, relinWindow, RLWE);

	return params;
}

template <class Element>
vector<shared_ptr<RGSWCiphertext<Element>>> GenerateBootstrappingKey(const typename Element::Vector &nv, const shared_ptr<LPCryptoParameters<Element>> cpr, const shared_ptr<RGSWPublicKey<Element>> pk){

	vector<shared_ptr<RGSWCiphertext<Element>>> result;

	typename Element::Vector as(nv);
	auto q = as.GetModulus();
	//Negate as vector
	for (usint i = 0; i < as.GetLength(); i++) {
		as[i] = q.ModSub(as[i], q);
		auto encoding = GetEncoding(cpr, as[i], q);
		auto cipher = RGSWOps<Element>::Encrypt(*pk, encoding);
		result.push_back(cipher);
	}

	return std::move(result);
}

template <class Element>
void runSingleCiphertextBootstrappingExperiment(usint m){
	//m should be in Zp
	NativeInteger q(512);
	NativeInteger p(5);
	usint dim = 10;
	m = m%p.ConvertToInt();

	auto dgg = make_shared<NativePoly::DggType>(2.0);
	auto dug = make_shared<NativePoly::DugType>();
	dug->SetModulus(q);

	shared_ptr<ILWEParams> params = make_shared<ILWEParams>(p,q,dim);

	params->SetDiscreteUniformGenerator(dug);
	params->SetDiscreteGaussianGenerator(dgg);

	std::cout << "starting standard LWE Key Generation "<< '\n';
	double start = currentDateTime();
	auto kp = ISLWEOps::KeyGen(params);
	double end = currentDateTime();
	std::cout << "standard LWE Key Genetation took "<< (end - start) <<" ms to finish\n\n";


	std::cout << "starting standard LWE encryption algorithm and encrypting message m = "<< m << '\n';
	start = currentDateTime();
	auto cipher = ISLWEOps::Encrypt(*kp.publickey, m);
	end = currentDateTime();
	std::cout << "standard LWE Encryption took "<< (end - start) <<" ms to finish\n";
	//#############Integer-LWE ends here##############

	//Initialize ciphertext to b
	auto a = cipher->GetA();
	auto b = cipher->GetB();

	auto cryptoParamRGSW = GetRGSWCryptoParams<Element>();

	//create beta value, beta = 2^-1Mod(p)
	NativeInteger beta(2);
	NativeInteger ringP = cryptoParamRGSW->GetPlaintextModulus();
	beta = beta.ModInverse(ringP);
	//NativeInteger ringN(cryptoParamRGSW->GetElementParams()->GetRingDimension());
	//auto betaN = (beta * ringN).Mod(ringP);
	//std::cout<<betaN<<'\n';

	// Initialize the public key containers.
	std::cout << "starting ring GSW scheme Key Genetation "<< '\n';
	start = currentDateTime();
	RGSWKeyPair<Element> kpRGSW = RGSWOps<Element>::KeyGen(cryptoParamRGSW);
	end = currentDateTime();
	std::cout << "ring GSW scheme Key Genetation took "<< (end - start) <<" ms to finish\n\n";

	auto bEncoding = GetEncoding<Element>(cryptoParamRGSW, b.ConvertToInt(), q.ConvertToInt());
	auto bootCipher = RGSWOps<Element>::ClearEncrypt(*kpRGSW.publicKey, bEncoding);
	usint l = std::ceil((double) q.GetMSB() / (double) 6);

	//usint message = ISLWEOps::Decrypt(cipher, *kp.secretkey);
	std::cout << "Generating bootstrapping key, will take time...\n";
	std::cout << "Get a coffee in the meantime...\n";
	auto bootKey = ISLWEOps::BootstrappingKeyGen<Element>(*kp.secretkey, 6, *kpRGSW.publicKey);
	std::cout << "Finished bootstrapping key gen\n";


	for (usint i = 0; i < dim; i++) {
		auto ai = a[i];
		ai = q.ModSub(ai, q); //ai = -a[i]
		for (usint j = 0; j < l; j++) {
			auto aij = NativeInteger(ai.GetDigitAtIndexForBase(j+1,1<<6));
			bootCipher = RGSWOps<Element>::Multiply(bootCipher,bootKey[aij.ConvertToInt()][i][j]);
		}
	}

	std::cout << "printing ciphertext in exponent encoding"
			<< RGSWOps<Element>::Decrypt(bootCipher, kpRGSW.secretKey) << "\n";


	auto aggVector = GenerateAggregationVector(cryptoParamRGSW);
	//std::cout << aggVector << '\n';
	auto aggCipher = RGSWOps<Element>::ClearEncrypt(*kpRGSW.publicKey, aggVector);
	bootCipher = RGSWOps<Element>::Multiply(bootCipher, aggCipher);

	auto finalValue = RGSWOps<Element>::Decrypt(bootCipher, kpRGSW.secretKey);
	//std::cout << finalValue << endl;

	NativeInteger finalMessage = finalValue[0].ModAdd(q>>1,p);
	finalMessage = finalMessage.ModMul(beta,p);

	std::cout << "final bootstrapped and decrypted ciphertext is " << finalMessage << endl;	

	//auto lweCipher = ConvertToSLWE(bootCipher,params);

	//auto checkResult = CheckLWE(lweCipher,kpRGSW.secretKey);

	//std::cout << checkResult<<'\n';

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

	RGSWKeyPair<Poly> kpRGSW = RGSWOps<Poly>::KeyGen(params);

	usint q = 16;

	usint b1 = 3;
	usint b2 = 4;

	auto b1Encoding = GetEncoding<Poly>(params, b1, q);
	cout<< b1Encoding<<'\n';
	auto b2Encoding = GetEncoding<Poly>(params, b2, q);
	cout<< b2Encoding<<'\n';

	auto b1Cipher = RGSWOps<Poly>::Encrypt(*kpRGSW.publicKey, b1Encoding);
	auto b2Cipher = RGSWOps<Poly>::Encrypt(*kpRGSW.publicKey, b2Encoding);

	auto bAddCipher = RGSWOps<Poly>::Multiply(b1Cipher, b2Cipher);

	auto result = RGSWOps<Poly>::Decrypt(bAddCipher, kpRGSW.secretKey);

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

	RGSWKeyPair<Poly> kpRGSW = RGSWOps<Poly>::KeyGen(params);

	usint q = 16;

	usint b1 = 10;
	usint b2 = 4;

	auto b1Encoding = GetEncoding<Poly>(params, b1, q);
	cout<< b1Encoding<<'\n';
	auto b2Encoding = GetEncoding<Poly>(params, b2, q);
	auto bSumEncoding = GetEncoding<Poly>(params, b2, q);
	b2Encoding = {1,1,1,1,1,1,1,1};
	bSumEncoding = {1,p-1,p-1,p-1,p-1,p-1,p-1,p-1};
	cout << b2Encoding << '\n';

	auto b1Cipher = RGSWOps<Poly>::Encrypt(*kpRGSW.publicKey, b1Encoding);
	auto b2Cipher = RGSWOps<Poly>::Encrypt(*kpRGSW.publicKey, b2Encoding);
	auto bSumCipher = RGSWOps<Poly>::Encrypt(*kpRGSW.publicKey, bSumEncoding);

	auto bAddCipher = RGSWOps<Poly>::Multiply(b1Cipher, b2Cipher);
	bAddCipher = RGSWOps<Poly>::Multiply(bSumCipher, bAddCipher);

	auto result = RGSWOps<Poly>::Decrypt(bAddCipher, kpRGSW.secretKey);

	cout << result << '\n'<<'\n';
}

template <class Element>
Element GenerateAggregationVector(const shared_ptr<LPCryptoParameters<Element>> cpr){
	Element one(cpr->GetElementParams(),COEFFICIENT,true);
	Element two(cpr->GetElementParams(),COEFFICIENT,true);

	usint N = cpr->GetElementParams()->GetRingDimension();
	auto p = cpr->GetPlaintextModulus();
	//auto beta = NativeInteger(2).ModInverse(p);

	for(usint i=0;i<N;i++){
		one[i] = typename Element::Integer(1);
	}
	two[0] = two.GetModulus()-typename Element::Integer(1);
	for(usint i=1;i<N;i++){
		two[i] = typename Element::Integer(1);
	}
	one.SwitchFormat();
	two.SwitchFormat();
	auto three = one*two;
	three.SwitchFormat();
	three = three.Mod(p);
	//three = three*beta;
	three = three.Mod(p);
	return std::move(three);
}

template <class Element>
shared_ptr<ILWECiphertext> ConvertToSLWE(const std::shared_ptr<RGSWCiphertext<Element>> rgswCipher,shared_ptr<ILWEParams> params){

	
	auto aRing = rgswCipher->GetElements().at(0).GetA();
	auto bRing = rgswCipher->GetElements().at(0).GetB();
	aRing.SwitchFormat(); //in coeff
	bRing.SwitchFormat(); //in coeff
	NativeVector aSLWE(aRing.GetRingDimension(),NativeInteger(aRing.GetModulus()));
	NativeInteger bSLWE(bRing[0]);

	aSLWE[0] = NativeInteger(aRing[0]);
	auto modulus = aRing.GetModulus();
	auto N = aRing.GetRingDimension();
	for (usint i = 1; i < N; i++) {
		auto val = modulus.ModSub(aRing[N-i],modulus);
		aSLWE[i] = NativeInteger(val);
	}

	auto dgg = make_shared<NativePoly::DggType>(2.0);
	auto dug = make_shared<NativePoly::DugType>();
	dug->SetModulus(NativeInteger(aRing.GetModulus()));
	NativeInteger p(rgswCipher->GetCryptoParameters()->GetPlaintextModulus());
	shared_ptr<ILWEParams> paramsFromRGSW = make_shared < ILWEParams > (p, NativeInteger(aRing.GetModulus()), aRing.GetLength());

	shared_ptr<ILWECiphertext> result = make_shared<ILWECiphertext>(paramsFromRGSW);

	result->SetA(aSLWE);
	result->SetB(bSLWE);
	return result;
}

template <class Element>
usint CheckLWE(shared_ptr<ILWECiphertext> lweCipher, shared_ptr<RGSWSecretKey<Element>> ringSK){
	const auto &a = lweCipher->GetA();
	const auto &s = ringSK->GetSecretKey();
	//auto modulus = a.GetModulus(); //modulus is same for both a and s
	
	usint N = a.GetLength();
	NativeVector sVec(N,s.GetModulus());
	for(usint i=0; i < N; i++){
		sVec[i] = s[i];
	}
	

	ILWESecretKey newSK(lweCipher->GetLWEParams());
	newSK.SetSKElement(sVec);

	usint message = ISLWEOps::Decrypt(lweCipher,newSK);
	cout << "message is "<< message << "\n";

	//form new parameter set
	NativeInteger qDash(512);
	auto dggDash = make_shared<NativePoly::DggType>(2.0);
	auto dugDash = make_shared<NativePoly::DugType>();
	dugDash->SetModulus(qDash);
	shared_ptr<ILWEParams> paramDash = make_shared<ILWEParams>(lweCipher->GetLWEParams()->GetPlaintextModulus(),qDash,N);
	paramDash->SetDiscreteUniformGenerator(dugDash);
	paramDash->SetDiscreteGaussianGenerator(dggDash);

	//mod reduce the cipgertext
	auto lweCipherReduced = ISLWEOps::ModSwitch(lweCipher,qDash);
	ILWESecretKey newSKModReduced(paramDash);
	auto sDash = sVec;
	sDash.SwitchModulus(qDash);
	newSKModReduced.SetSKElement(sDash);

	message = ISLWEOps::Decrypt(lweCipherReduced,newSKModReduced);
	cout << "message is "<< message << "\n";

	return 0;
}

void runProposalExperimentForSize(usint n,usint r,usint q){
	//m shouuld be in Zp
	NativeInteger qNI(q);
	NativeInteger p(5);
	usint dim = n;
	usint m = 1;

	auto dgg = make_shared < NativePoly::DggType > (2.0);
	auto dug = make_shared<NativePoly::DugType>();
	dug->SetModulus(qNI);

	shared_ptr<ILWEParams> params = make_shared < ILWEParams > (p, qNI, dim);

	params->SetDiscreteUniformGenerator(dug);
	params->SetDiscreteGaussianGenerator(dgg);

	auto kp = ISLWEOps::KeyGen(params);

	auto cipher = ISLWEOps::Encrypt(*kp.publickey, m);

	auto kpNew = ISLWEOps::KeyGen(params);

	auto hint = ISLWEOps::KeySwitchGen(*kp.secretkey,*kpNew.secretkey,r);

	usint sizeInBytes = 0;

	for(usint i=0;i<hint.size();i++){
		for(usint j=0;j<hint[0].size();j++){
			sizeInBytes+= hint[i][j]->GetSizeInBytes();
		}
	}

	std::cout<< "size of KeySwitchHint is\t"<<sizeInBytes<<'\n';
}

template <class Element>
void runProposalExperimentForBootstrappingKeySize(usint n,usint r, usint q){

	//m shouuld be in Zp
	NativeInteger qNI(q);
	NativeInteger p(5);
	usint dim = n;
	usint m = 1;//message

	auto dgg = make_shared<NativePoly::DggType>(2.0);
	auto dug = make_shared<NativePoly::DugType>();
	dug->SetModulus(qNI);

	shared_ptr<ILWEParams> params = make_shared<ILWEParams>(p,qNI,dim);

	params->SetDiscreteUniformGenerator(dug);
	params->SetDiscreteGaussianGenerator(dgg);

	auto kp = ISLWEOps::KeyGen(params);

	auto cipher = ISLWEOps::Encrypt(*kp.publickey, m);
	//#############Integer-LWE ends here##############

	//Initialize ciphertext to b
	auto a = cipher->GetA();
	auto b = cipher->GetB();

	auto cryptoParamRGSW = GetRGSWCryptoParams<Element>();

	//create beta value, beta = 2^-1Mod(p)
	NativeInteger beta(2);
	NativeInteger ringP = cryptoParamRGSW->GetPlaintextModulus();
	beta = beta.ModInverse(ringP);
	NativeInteger ringN(cryptoParamRGSW->GetElementParams()->GetRingDimension());
	auto betaN = (beta * ringN).Mod(ringP);
	std::cout<<betaN<<'\n';

	// Initialize the public key containers.
	RGSWKeyPair<Element> kpRGSW = RGSWOps<Element>::KeyGen(cryptoParamRGSW);

	auto bEncoding = GetEncoding<Element>(cryptoParamRGSW, b.ConvertToInt(), qNI.ConvertToInt());
	auto bootCipher = RGSWOps<Element>::Encrypt(*kpRGSW.publicKey, bEncoding);
	std::cout << "size of single ciphertext \t"<<bootCipher->GetSizeInBytes()<<'\n';
	//usint l = std::ceil((double)qNI.GetMSB()/(double)r);


	//usint message = ISLWEOps::Decrypt(cipher, *kp.secretkey);
	std::cout<<"Generating bootstrapping key, will take time...\n";
	std::cout<<"Get a coffee in the meantime...\n";
	double start = currentDateTime();
	auto bootKey = ISLWEOps::BootstrappingKeyGen(*kp.secretkey,r,*kpRGSW.publicKey);
	double end = currentDateTime();
	std::cout<<"Finished bootstrapping key gen\n";
	std::cout<<"bootstrapping key gen took\t"<< end-start <<" time in ms\n";

	usint bootSize = 0;

	for (usint i = 0; i < bootKey.size(); i++) {
		for (usint j = 0; j < bootKey[i].size(); j++) {
			for (usint k = 0; k < bootKey[i][j].size(); k++) {
				bootSize+= bootKey[i][j][k]->GetSizeInBytes();
			}
		}
	}

	std::cout << "printing boot key size\t"<< bootSize <<'\n';


}

template <class Element>
void runProposalExperimentForRGSWTimings(){

	usint m = 512;
	usint p = 5;
	typename Element::Integer modulusP(p);
	typename Element::Integer modulusQ("1237940039285380274899136513");
	typename Element::Integer rootOfUnity("1237517859929867934426131003");

	float stdDev = 4;
	float assm = 9;//assuranceMeasure
	float sL = 1.006;//securityLevel
	usint relinWindow = 8;
	auto ep = make_shared < typename Element::Params > (m, modulusQ, rootOfUnity);

	auto cryptoParamRGSW = make_shared <LPCryptoParametersBGV<Element>> (ep, p, stdDev, assm, sL, relinWindow, RLWE);

	double start = currentDateTime();

	RGSWKeyPair<Element> kpRGSW = RGSWOps<Element>::KeyGen(cryptoParamRGSW);

	double end = currentDateTime();

	std::cout << "RGSW KeyGen time\t"<< (end-start)<<'\n';

	auto ptxt1 = GetEncoding<Element>(cryptoParamRGSW, 10, m);

	auto ptxt2 =  GetEncoding<Element>(cryptoParamRGSW, 20, m);


	start = currentDateTime();
	auto cipher1 = RGSWOps<Element>::Encrypt(*kpRGSW.publicKey, ptxt1);
	end = currentDateTime();
	std::cout << "RGSW Encrypt time\t"<< (end-start)<<'\n';

	start = currentDateTime();
	auto cipher2 = RGSWOps<Element>::Encrypt(*kpRGSW.publicKey, ptxt2);
	end = currentDateTime();
	std::cout << "RGSW Encrypt time\t"<< (end-start)<<'\n';

	start = currentDateTime();
	auto cipher3 = RGSWOps<Element>::Multiply(cipher1,cipher2);
	end = currentDateTime();
	std::cout << "RGSW EvalMult time\t"<< (end-start)<<'\n';


	start = currentDateTime();
	auto finalValue = RGSWOps<Element>::Decrypt(cipher3, kpRGSW.secretKey);
	end = currentDateTime();
	std::cout << "RGSW Decrypt time\t"<< (end-start)<<'\n';
}







