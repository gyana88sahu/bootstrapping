#ifndef LBCRYPTO_CRYPTO_CRT_FUNC_CPP
#define LBCRYPTO_CRYPTO_CRT_FUNC_CPP

#include "crtFunc.h"

namespace lbcrypto{

template<class T>
std::vector<T> modReduce(const T& a1, const T& a2, const T& a3, usint p) {

	std::vector<T> result;
	T a(a1);
	T b(a2);
	T c(a3);

	a.SwitchFormat();
	b.SwitchFormat();
	c.SwitchFormat();

	T towerT(c);
	T d(c);

	typename T::Integer ptm(p);
	typename T::Integer qt(c.GetModulus());

	typename T::Integer v(qt.ModInverse(ptm));
	typename T::Integer aDash((v * qt).ModSub(1, ptm * qt));

	d.SwitchModulus( ptm*qt, d.GetRootOfUnity() );

	T delta(d.Times(aDash));

	T temp(delta);
	temp.SwitchModulus(a.GetModulus(),a.GetRootOfUnity());
	a += temp;

	temp = delta;
	temp.SwitchModulus(b.GetModulus(),b.GetRootOfUnity());
	b += temp;

	temp = delta;
	temp.SwitchModulus(c.GetModulus(), c.GetRootOfUnity());
	c += temp;

	std::vector<typename T::Integer> qtInverseModQi;
	qtInverseModQi.push_back(qt.ModInverse(a.GetModulus()));
	qtInverseModQi.push_back(qt.ModInverse(b.GetModulus()));

	a = a*qtInverseModQi[0];
	b = b*qtInverseModQi[1];

	a.SwitchFormat();
	b.SwitchFormat();

	result.push_back(std::move(a));
	result.push_back(std::move(b));

	return std::move(result);
}

template<class T>
Poly SM(const T &a, const BigInteger &q){
	auto ep = make_shared < typename Poly::Params > (a.GetCyclotomicOrder(), q, typename Poly::Integer(0));
	Poly result(ep, a.GetFormat(), true);
	typename Poly::Integer oldMod(a.GetModulus().ToString());
	typename Poly::Integer halfQ(oldMod);
	halfQ >>= 1;
	for (usint i = 0; i < a.GetRingDimension(); i++) {
		typename Poly::Integer temp(a[i].ToString());
		if (temp > halfQ) {
			temp += q;
			temp = temp.ModSub(oldMod, q);
		}
		result[i] = temp;
	}

	return result;
}

template <class T>
T CRT(const T &n1,const T &n2,const T &q1,const T &q2){
	return T(0);
}

template <>
inline BigInteger CRT<BigInteger>(const BigInteger &n1, const BigInteger &n2,	const BigInteger &q1, const BigInteger &q2) {
	BigInteger q = q1 * q2;
	BigInteger b1 = q / q1;
	BigInteger b2 = q / q2;

	BigInteger x1 = b1.ModInverse(q1);
	BigInteger x2 = b2.ModInverse(q2);

	BigInteger result1 = (b1 * x1 * n1).Mod(q);
	BigInteger result2 = (b2 * x2 * n2).Mod(q);

	BigInteger result = result1.ModAdd(result2,q);

	return result;
}

template <>
inline NativeInteger CRT<NativeInteger>(const NativeInteger &n1, const NativeInteger &n2,	const NativeInteger &q1, const NativeInteger &q2) {

	BigInteger bgN1(n1.ToString());
	BigInteger bgN2(n2.ToString());

	BigInteger bgQ1(q1.ToString());
	BigInteger bgQ2(q2.ToString());

	BigInteger q = bgQ1 * bgQ2;
	if (q.GetMSB() > 63) {
		throw std::runtime_error("overflow in modulo size");
	}

	BigInteger r = CRT<BigInteger>(bgN1, bgN2, bgQ1, bgQ2);

	NativeInteger result(r.ConvertToInt());

	return result;
}

//Expects a and b in EVAL ; output is in COEFF
template <class T>
const T CRTPolynomial(const T &a, const T &b){

	if(a.GetFormat()!=EVALUATION || b.GetFormat()!=EVALUATION){
		throw std::runtime_error("wrong format");
	}

	const typename T::Integer& q1 = a.GetModulus();
	const typename T::Integer& q2 = b.GetModulus();

	T aCopy(a);
	T bCopy(b);

	aCopy.SwitchFormat();
	bCopy.SwitchFormat();

	typename T::Integer q = q1 * q2;

	typename T::Integer r("0");
	auto params = make_shared < typename T::Params > (a.GetCyclotomicOrder(), q, r);
	T result(params, COEFFICIENT,true);
	result.SetValuesToZero();
	usint n = a.GetRingDimension();

	for (usint i = 0; i < n; i++) {
		typename T::Integer num1(aCopy[i]);
		typename T::Integer num2(bCopy[i]);

		result[i] = CRT(num1, num2, q1, q2);
	}

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


}
#endif
