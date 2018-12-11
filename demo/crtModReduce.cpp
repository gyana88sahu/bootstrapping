#include <palisade.h>
#include "../src/crtFunc.cpp"

using namespace std;
using namespace lbcrypto;

template <class T>
void crtModReduceExp();

int main(){

	crtModReduceExp<NativePoly>();

	return 0;
}


template <class T>
void crtModReduceExp(){
	usint m = 16;
	usint p = 5;

	typename T::Integer q1("33554593");
	typename T::Integer r1("31348180");
	typename T::Integer q2("67108913");
	typename T::Integer r2("67047349");
	typename T::Integer q3("134218081");
	typename T::Integer r3("127268772");

	BigInteger q("302233920629906514542129");
	BigInteger r("0 ");

	typename T::Integer qDash(q1*q2);
	typename T::Integer rDash(0);

	float stdDev = 4;
	float assm = 9; //assuranceMeasure
	float sL = 1.006; //securityLevel
	usint relinWindow = 1;

	auto ep1 = make_shared<typename T::Params>(m, q1, r1);
	auto params1 = make_shared < LPCryptoParametersBGV <T>> (ep1, p, stdDev, assm, sL, relinWindow, RLWE);

	auto ep2 = make_shared<typename T::Params>(m, q2, r2);
	auto params2 = make_shared < LPCryptoParametersBGV<T>> (ep2, p, stdDev, assm, sL, relinWindow, RLWE);

	auto ep3 = make_shared<typename T::Params>(m, q3, r3);
	auto params3 = make_shared < LPCryptoParametersBGV <T>> (ep3, p, stdDev, assm, sL, relinWindow, RLWE);

	auto ep = make_shared<typename Poly::Params>(m, q, r);
	auto params = make_shared < LPCryptoParametersBGV < Poly >> (ep, p, stdDev, assm, sL, relinWindow, RLWE);

	auto epDash = make_shared<typename T::Params>(m, qDash, rDash);
	auto paramsDash = make_shared < LPCryptoParametersBGV <T>> (epDash, p, stdDev, assm, sL, relinWindow, RLWE);

	T s1(params1->GetDiscreteGaussianGenerator(), ep1, COEFFICIENT);
	T s2(s1);
	T s3(s1);
	T sDash(s1);
	s2.SwitchModulus(q2, r2);
	s3.SwitchModulus(q3, r3);
	auto s = SM(s1, q);
	sDash.SwitchModulus(qDash, rDash);

	//make EVAL s1,s2,s3
	s1.SwitchFormat();
	s2.SwitchFormat();
	s3.SwitchFormat();

	typename T::DugType dug;
	const typename T::TugType tug;
	//generate a_i's
	T a1(dug, ep1, EVALUATION);
	T a2(dug, ep2, EVALUATION);
	T a3(dug, ep3, EVALUATION);

	//error generation
	T e1(tug, ep1, EVALUATION);
	e1.SwitchFormat();
	T e2(e1);
	e2.SwitchModulus(q2, r2);
	T e3(e1);
	e3.SwitchModulus(q3, r3);

	e1.SwitchFormat();
	e2.SwitchFormat();
	e3.SwitchFormat();

	//Generate b's
	T b1 = a1 * s1 + p * e1;
	T b2 = a2 * s2 + p * e2;
	T b3 = a3 * s3 + p * e3;

	//Run mod reduce on the lwe samples
	auto lweA = modReduce(a1, a2, a3, p);//it takes everything in EVAL domain and outputs in EVAL domain
	auto lweB = modReduce(b1, b2, b3, p);//it takes everything in EVAL domain and outputs in EVAL domain


	T a1Dash(lweA[0]);
	T a2Dash(lweA[1]);
	T b1Dash(lweB[0]);
	T b2Dash(lweB[1]);

	auto origCheck1 = b1 - a1 * s1;
	auto origCheck2 = b2 - a2 * s2;


	auto check1 = b1Dash - a1Dash * s1;
	auto check2 = b2Dash - a2Dash * s2;

	check1.SwitchFormat();
	check2.SwitchFormat();
	origCheck1.SwitchFormat();
	origCheck2.SwitchFormat();

	std::cout << "Printing check1 polynomial in COEFF domain\n";
	std::cout << check1 << '\n';
	std::cout << '\n';

	std::cout << "Printing check2 polynomial in COEFF domain\n";
	std::cout << check2 << '\n';
	std::cout << '\n';

	std::cout << "Printing origCheck1 polynomial in COEFF domain\n";
	std::cout << origCheck1 << '\n';
	std::cout << '\n';

	std::cout << "Printing origCheck2 polynomial in COEFF domain\n";
	std::cout << origCheck2 << '\n';
	std::cout << '\n';

	auto bDash = CRTPoly<T>(b1Dash, b2Dash);
	auto aDash = CRTPoly<T>(a1Dash, a2Dash);

	auto aDashsDash = PolyMult(aDash,sDash);

	std::cout << "Printing aDashsDash \n"<< aDashsDash << '\n' << '\n';
	std::cout << "Printing bDash \n"<< bDash << '\n' << '\n';



}
