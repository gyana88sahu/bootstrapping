#include <palisade.h>

using namespace std;
using namespace lbcrypto;

typedef NativeInteger Int;
typedef NativePoly Element;

const Poly CRTPoly(const Element &a, const Element &b, const Element &c);
BigInteger CRT(const BigInteger &n1,const BigInteger &n2,const BigInteger &n3,const BigInteger &q1,const BigInteger &q2,const BigInteger &q3);

Poly SM(const Element &a, const BigInteger &q);

template <class T>
T PolyMult(const T &a, const T &b);

void threeModuliExp();

int main(){


	threeModuliExp();

	return 0;
}

const Poly CRTPoly(const Element &a, const Element &b, const Element &c){
	BigInteger q1(a.GetModulus().ToString());
	BigInteger q2(b.GetModulus().ToString());
	BigInteger q3(c.GetModulus().ToString());

	Element aCopy(a);
	Element bCopy(b);
	Element cCopy(c);

	aCopy.SwitchFormat();
	bCopy.SwitchFormat();
	cCopy.SwitchFormat();

	BigInteger q = q1 * q2 * q3;
	BigInteger r("0");
	auto params = make_shared < typename Poly::Params > (a.GetCyclotomicOrder(), q, r);
	Poly result(params, COEFFICIENT,true);

	for (usint i = 0; i < a.GetRingDimension(); i++) {
		BigInteger num1(aCopy[i].ToString());
		BigInteger num2(bCopy[i].ToString());
		BigInteger num3(cCopy[i].ToString());

		result[i] = CRT(num1, num2, num3, q1, q2, q3);
	}

	return result;
}

BigInteger CRT(const BigInteger &n1,const BigInteger &n2,const BigInteger &n3,const BigInteger &q1,const BigInteger &q2,const BigInteger &q3){
	BigInteger q = q1 * q2 * q3;
	BigInteger b1 = q / q1;
	BigInteger b2 = q / q2;
	BigInteger b3 = q / q3;

	BigInteger x1 = b1.ModInverse(q1);
	BigInteger x2 = b2.ModInverse(q2);
	BigInteger x3 = b3.ModInverse(q3);

	BigInteger result1 = (b1 * x1 * n1).Mod(q);
	BigInteger result2 = (b2 * x2 * n2).Mod(q);
	BigInteger result3 = (b3 * x3 * n3).Mod(q);

	BigInteger result = result1.ModAdd(result2, q);
	result = result.ModAdd(result3, q);

	return result;
}

template <class T> //multiplication in COEFF form, needed when q is composite
T PolyMult(const T &a, const T &b){

	if (a.GetFormat() == EVALUATION || b.GetFormat() == EVALUATION) {
		throw std::runtime_error("wrong format");
	}

	T result(a);
	result.SetValuesToZero();
	usint n = a.GetRingDimension();
	const typename T::Integer& modulus = a.GetModulus();

	for (usint i = 0; i < n; i++) {
		typename T::Integer temp(0);
		for (usint j = 0; j < n; j++) {
			temp = a[i].ModMul(b[j],modulus);
			usint idx = (i + j);
			if (idx >= n) {
				temp = modulus.ModSub(temp, modulus);
				idx = idx % n;
			}
			result[idx] = result[idx].ModAdd(temp, modulus);
		}
	}

	return result;
}

Poly SM(const Element &a, const BigInteger &q){
	auto ep = make_shared < typename Poly::Params > (a.GetCyclotomicOrder(), q, BigInteger(0));
	Poly result(ep, a.GetFormat(),true);
	BigInteger oldMod(a.GetModulus().ToString());
	BigInteger halfQ(oldMod);
	halfQ>>=1;
	for(usint i=0;i<a.GetRingDimension();i++){
		BigInteger temp(a[i].ToString());
		if(temp>halfQ){
			temp += q ;
			temp = temp.ModSub(oldMod,q);
		}
		result[i] = temp;
	}

	return result;
}

void threeModuliExp(){

	usint m = 16;
	usint p = 5;

	Int q1("33554593");
	Int r1("31348180");
	Int q2("67108913");
	Int r2("67047349");
	Int q3("134218081");
	Int r3("127268772");

	BigInteger q("302233920629906514542129");
	BigInteger r("0 ");

	float stdDev = 4;
	float assm = 9; //assuranceMeasure
	float sL = 1.006; //securityLevel
	usint relinWindow = 1;

	auto ep1 = make_shared<typename Element::Params>(m, q1, r1);
	auto params1 = make_shared < LPCryptoParametersBGV < Element >> (ep1, p, stdDev, assm, sL, relinWindow, RLWE);

	auto ep2 = make_shared<typename Element::Params>(m, q2, r2);
	auto params2 = make_shared < LPCryptoParametersBGV	< Element >> (ep2, p, stdDev, assm, sL, relinWindow, RLWE);

	auto ep3 = make_shared<typename Element::Params>(m, q3, r3);
	auto params3 = make_shared < LPCryptoParametersBGV < Element >> (ep3, p, stdDev, assm, sL, relinWindow, RLWE);

	auto ep = make_shared<typename Poly::Params>(m, q, r);
	auto params = make_shared < LPCryptoParametersBGV < Poly >> (ep, p, stdDev, assm, sL, relinWindow, RLWE);

	//generate a secret key s
	Element s1(params1->GetDiscreteGaussianGenerator(), ep1, COEFFICIENT);
	Element s2(s1);
	Element s3(s1);
	s2.SwitchModulus(q2, r2);
	s3.SwitchModulus(q3, r3);
	auto s = SM(s1, q);

	//printing s1,s2,s3
	std::cout << "printing s1\n";
	std::cout << s1 << '\n';
	std::cout << "printing s2\n";
	std::cout << s2 << '\n';
	std::cout << "printing s3\n";
	std::cout << s3 << '\n';
	std::cout << "printing s\n";
	std::cout << s << '\n';

	//make EVAL s1,s2,s3
	s1.SwitchFormat();
	s2.SwitchFormat();
	s3.SwitchFormat();

	typename Element::DugType dug;
	const typename Element::TugType tug;
	//generate a_i's
	Element a1(dug, ep1, EVALUATION);
	Element a2(dug, ep2, EVALUATION);
	Element a3(dug, ep3, EVALUATION);

	//error generation
	Element e1(tug, ep1, EVALUATION);
	e1.SwitchFormat();
	Element e2(e1);
	e2.SwitchModulus(q2, r2);
	Element e3(e1);
	e3.SwitchModulus(q3, r3);

	e1.SwitchFormat();
	e2.SwitchFormat();
	e3.SwitchFormat();

	//Generate b's
	Element b1 = a1 * s1 + p * e1;
	Element b2 = a2 * s2 + p * e2;
	Element b3 = a3 * s3 + p * e3;

	//check if CRT version of all three satisfies lwe
	Poly a = CRTPoly(a1, a2, a3);
	Poly b = CRTPoly(b1, b2, b3);
	Poly e = CRTPoly(e1, e2, e3);

	std::cout << "printing e\n";
	std::cout << e << '\n';

	std::cout << "printing a\n";
	std::cout << a << '\n';

	std::cout << "printing b\n";
	std::cout << b << '\n';
	auto as = PolyMult(a, s);

	std::cout << "printing as\n";
	std::cout << as << std::endl;

}
