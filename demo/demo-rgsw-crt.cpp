#include "palisade.h"
//#include "../src/crtpoly-impl.h"
#include "../src/gsw-impl.cpp"

using namespace lbcrypto;
using namespace std;

template<class T>
void EncryptDecryptTest();

template<class T>
void EvalMultTest();

template<class T>
void EvalAddTest();

int main() {

	//EncryptDecryptTest<CRTPoly>();
	EvalMultTest<CRTPoly>();

	return 0;
}

template<class T>
void EncryptDecryptTest() {

	usint m = 16;
	usint p = 5;
	usint numOfTower = 3;
	NativeInteger modulusP(p);

	std::vector < NativeInteger > moduli(numOfTower);
	std::vector < NativeInteger > rootsOfUnity(numOfTower);

	moduli[0] = NativeInteger(33554593);
	moduli[1] = NativeInteger(134218081);
	moduli[2] = NativeInteger(536871089);

	rootsOfUnity[0] = NativeInteger(31348180);
	rootsOfUnity[1] = NativeInteger(127268772);
	rootsOfUnity[2] = NativeInteger(469314841);

	float stdDev = 4;
	float assm = 9; //assuranceMeasure
	float sL = 1.006; //securityLevel
	usint relinWindow = 1;
	auto ep = make_shared<typename T::Params>(m, moduli, rootsOfUnity);

	auto params = make_shared<LPCryptoParametersBGV<T>>(ep, p, stdDev, assm, sL, relinWindow, RLWE);

	auto kp = RGSWOps<T>::KeyGen(params);

	T message(ep, COEFFICIENT);

	message = {0,1,2,0};

	std::cout << "message to be encrypted is \n\n" << message << "\n\n";

	auto cipher = RGSWOps<T>::Encrypt(*kp.publicKey, message);

	//std::cout << "ciphertext is shown as \n\n"<< cipher << "\n\n";
	auto decryptResult = RGSWOps<T>::Decrypt(cipher, kp.secretKey);

	std::cout << decryptResult << '\n';

}

template<class T>
void EvalMultTest() {

	usint m = 16;
	usint p = 5;
	usint numOfTower = 3;
	NativeInteger modulusP(p);

	std::vector < NativeInteger > moduli(numOfTower);
	std::vector < NativeInteger > rootsOfUnity(numOfTower);

	moduli[0] = NativeInteger(33554593);
	moduli[1] = NativeInteger(134218081);
	moduli[2] = NativeInteger(536871089);

	rootsOfUnity[0] = NativeInteger(31348180);
	rootsOfUnity[1] = NativeInteger(127268772);
	rootsOfUnity[2] = NativeInteger(469314841);

	float stdDev = 4;
	float assm = 9; //assuranceMeasure
	float sL = 1.006; //securityLevel
	usint relinWindow = 1;
	auto ep = make_shared<typename T::Params>(m, moduli, rootsOfUnity);

	auto params = make_shared<LPCryptoParametersBGV<T>>(ep, p, stdDev, assm, sL, relinWindow, RLWE);

	auto kp = RGSWOps<T>::KeyGen(params);

	T message1(ep, COEFFICIENT);

	message1 = {0,1,0,0};

	T message2(ep, COEFFICIENT);

	message2 = {0,0,1,0};

	auto cipher1 = RGSWOps<T>::Encrypt(*kp.publicKey, message1);

	auto cipher2 = RGSWOps<T>::Encrypt(*kp.publicKey, message2);

	std::cout << "Encryption finished\n\n";

	auto cipher3 = RGSWOps<T>::Multiply(cipher1, cipher2);

}

template<class T>
void EvalAddTest() {

}

