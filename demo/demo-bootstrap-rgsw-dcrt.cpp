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

template <class Element>
vector<shared_ptr<RGSWCiphertext<Element>>> GenerateBootstrappingKey(const typename Element::Vector &nv, const shared_ptr<LPCryptoParameters<Element>> cpr, const shared_ptr<RGSWPublicKey<Element>> pk);


template <class Element>
void runSingleCiphertextBootstrappingExperiment(usint m);

template <class Element>
Element GenerateAggregationVector(const shared_ptr<LPCryptoParameters<Element>> cpr);

template <class Element>
shared_ptr<ILWECiphertext> ConvertToSLWE(const std::shared_ptr<RGSWCiphertext<Element>> rgswCipher,shared_ptr<ILWEParams> params);

template <class Element>
usint CheckLWE(shared_ptr<ILWECiphertext> lweCipher, shared_ptr<RGSWSecretKey<Element>> ringSK);



int main(int argc, char *argv[]){

	runSingleCiphertextBootstrappingExperiment<DCRTPoly>(1);


	return 0;

}

template <class Element>
Element GetEncoding(const shared_ptr<LPCryptoParameters<Element>> cryptoParams,usint message, usint q){
	//message is in Zq

	const auto &elemParams = cryptoParams->GetElementParams();
	const auto& modulus = elemParams->GetModulus();
	cout << modulus << endl;
	usint p = cryptoParams->GetPlaintextModulus();
	usint m = elemParams->GetCyclotomicOrder();
	usint N = elemParams->GetRingDimension(); //ring dimension

	std::vector<PolyImpl<NativeVector>> towers;

	for (usint i = 0; i < elemParams->GetParams().size(); i++) {
		PolyImpl<NativeVector> tower(elemParams->GetParams().at(i), COEFFICIENT, true);
		NativeVector vec(N, elemParams->GetParams().at(i)->GetModulus());

		usint idx = (m/q)*message; //idx is between 0 to 2N-1

		if (idx > N - 1) {
			idx = idx % N;
			vec[idx] = NativeInteger(p - 1);
		}
		else {
			vec[idx] = NativeInteger(1);
		}

		tower.SetValues(vec, COEFFICIENT);
		towers.push_back(std::move(tower));

	}

	Element result(towers);

	return std::move(result);
}

template <class Element>
Element GetEncoding(const shared_ptr<LPCryptoParameters<Element>> cryptoParams,typename Element::Integer &message, typename Element::Integer &q){
	//message is in Zq
	return GetEncoding<Element>(cryptoParams, message.ConvertToInt(), q.ConvertToInt());
}

template <class Element>
const shared_ptr<LPCryptoParameters<Element>> GetRGSWCryptoParams(){
	usint m = 512;
	usint p = 5;
	usint numOfTower = 5;
	typename Element::Integer modulusP(p);

	std::vector<NativeInteger> moduli(numOfTower);
	std::vector<NativeInteger> rootsOfUnity(numOfTower);

	moduli[0] = NativeInteger(33556993);
	moduli[1] = NativeInteger(134221313);
	moduli[2] = NativeInteger(536874497);
	moduli[3] = NativeInteger(2147484161);
	moduli[4] = NativeInteger(8589952001);

	rootsOfUnity[0] = NativeInteger(33487944);
	rootsOfUnity[1] = NativeInteger(134198785);
	rootsOfUnity[2] = NativeInteger(534843467);
	rootsOfUnity[3] = NativeInteger(2132641163);
	rootsOfUnity[4] = NativeInteger(8568593202);



	float stdDev = 4;
	float assm = 9;//assuranceMeasure
	float sL = 1.006;//securityLevel
	usint relinWindow = 16;
	auto ep = make_shared < typename Element::Params > (m, moduli, rootsOfUnity);


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
	cout << "Printing a "<< a << endl;
	cout << "Printing b "<< b << endl;

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
		if(i>1 && i%2==0)
			bootCipher->ModReduce();
	}

	std::cout << "printing ciphertext in exponent encoding"
			<< RGSWOps<Element>::Decrypt(bootCipher, kpRGSW.secretKey) << "\n";


	auto aggVector = GenerateAggregationVector(cryptoParamRGSW);
	//std::cout << aggVector << '\n';
	auto aggCipher = RGSWOps<Element>::ClearEncrypt(*kpRGSW.publicKey, aggVector);
	bootCipher = RGSWOps<Element>::Multiply(bootCipher, aggCipher);

	auto finalValue = RGSWOps<Element>::Decrypt(bootCipher, kpRGSW.secretKey);
	//std::cout << finalValue << endl;

	auto finalMessage = finalValue[0].ModAdd(q>>1,p);
	cout << "Type is "<< typeid(finalMessage).name()<<'\n';
	finalMessage = finalMessage.ModMul(beta,p);

	std::cout << "final bootstrapped and decrypted ciphertext is " << finalMessage << endl;	

	//auto lweCipher = ConvertToSLWE(bootCipher,params);

	//auto checkResult = CheckLWE(lweCipher,kpRGSW.secretKey);

	//std::cout << checkResult<<'\n';

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







