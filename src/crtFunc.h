#ifndef LBCRYPTO_CRYPTO_CRT_FUNC_H
#define LBCRYPTO_CRYPTO_CRT_FUNC_H

#include "palisade.h"

namespace lbcrypto{

template <class T>
std::vector<T> modReduce(const T& a1, const T& a2, const T& a3, usint ptm);


template<class T>
Poly SM(const T &a, const BigInteger &q);

template <class T>
const T CRTPolynomial(const T &a, const T &b);

//2 parameter crt with arb integer
template <class T>
T CRT(const T &n1,const T &n2,const T &q1,const T &q2);

template <class T>
T PolyMult(const T &a, const T &b);

}

#endif
