#include <palisade.h>
#include "../src/crtFunc.cpp"

using namespace std;
using namespace lbcrypto;

typedef NativeInteger Int;
typedef NativePoly Element;


template <class T>
void crtMultExperiment();

void crtTest();

int main(){

	//crtTest();

	crtMultExperiment<Element>();
	//crtMultExperiment<Poly>();
	return 0;
}

void crtTest(){
	Int q1("33554593");
	Int q2("67108913");

	Int num1(29284106);
	Int num2(7628453);


	Int res = CRT(num1, num2, q1, q2);

	std::cout << res << endl;
}

template <class T>
void crtMultExperiment(){
	usint m = 16;
	usint p = 5;

	typename T::Integer q1("33554593");
	typename T::Integer r1("31348180");
	typename T::Integer q2("67108913");
	typename T::Integer r2("67047349");

	typename T::Integer q("2251812262387409");
	typename T::Integer r("0");

	float stdDev = 4;
	float assm = 9; //assuranceMeasure
	float sL = 1.006; //securityLevel
	usint relinWindow = 1;

	auto ep1 = make_shared<typename T::Params>(m, q1, r1);
	auto params1 = make_shared < LPCryptoParametersBGV
			< T >> (ep1, p, stdDev, assm, sL, relinWindow, RLWE);

	auto ep2 = make_shared<typename T::Params>(m, q2, r2);
	auto params2 = make_shared < LPCryptoParametersBGV
			< T >> (ep2, p, stdDev, assm, sL, relinWindow, RLWE);

	auto ep = make_shared<typename T::Params>(m, q, r);
	auto params = make_shared < LPCryptoParametersBGV
			< T >> (ep, p, stdDev, assm, sL, relinWindow, RLWE);

	//generate a secret key s
	T s1(params1->GetDiscreteGaussianGenerator(), ep1, COEFFICIENT);
	T s2(s1);
	T s(s1);

	s2.SwitchModulus(q2, r2);
	s.SwitchModulus(q, r);

	//printing s1,s2,s3
	std::cout << "printing s1\n";
	std::cout << s1 << '\n';
	std::cout << "printing s2\n";
	std::cout << s2 << '\n';
	std::cout << "printing s\n";
	std::cout << s << '\n';


	//make EVAL s1,s2,s3
	s1.SwitchFormat();
	s2.SwitchFormat();

	typename T::DugType dug;
	const typename T::TugType tug;
	//generate lwe sample a1, b1
	T a1(dug, ep1, EVALUATION);

	//generate lwe sample a2, b2
	T a2(dug, ep2, EVALUATION);

	T a = CRTPoly(a1, a2);

	a1.SwitchFormat();
	a2.SwitchFormat();

	cout << "Printing a1 polynomial in COEFF " << '\n' << a1 << '\n';
	cout << "Printing a2 polynomial in COEFF " << '\n' << a2 << '\n';

	a1.SwitchFormat();
	a2.SwitchFormat();

	cout << "Printing a Polynomial " << a << '\n';

	auto as1 = a1 * s1;
	auto as2 = a2 * s2;
	auto as = PolyMult(a, s);
	cout << as << endl;
	cout << CRTPoly(as1, as2) << endl;

}


