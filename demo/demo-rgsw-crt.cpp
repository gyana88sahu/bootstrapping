#include "palisade.h"
#include "../src/crtpoly.cpp"



using namespace lbcrypto;
using namespace std;


template class CRTPolyImpl<BigVector>;

typedef CRTPolyImpl<BigVector> CRTPoly;


template <class T>
void EncryptDecryptTest();

int main(){

	EncryptDecryptTest<DCRTPoly>();
	return 0;
}

template <class T>
void EncryptDecryptTest(){

	usint m = 16;
	usint p = 5;
	usint numOfTower = 3;
	NativeInteger modulusP(p);

	std::vector <NativeInteger> moduli(numOfTower);
	std::vector <NativeInteger> rootsOfUnity(numOfTower);

	moduli[0] = NativeInteger(33554593);
	moduli[1] = NativeInteger(134218081);
	moduli[2] = NativeInteger(536871089);

	rootsOfUnity[0] = NativeInteger(31348180);
	rootsOfUnity[1] = NativeInteger(127268772);
	rootsOfUnity[2] = NativeInteger(469314841);

	float stdDev = 4;
	float assm = 9; //assuranceMeasure
	float sL = 1.006; //securityLevel
	usint relinWindow = 16;
	auto ep = make_shared<typename T::Params>(m, moduli, rootsOfUnity);

	auto params = make_shared <LPCryptoParametersBGV<T>> (ep, p, stdDev, assm, sL, relinWindow, RLWE);

}
