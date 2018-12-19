#include "crtpoly.h"
#include <memory>
using std::shared_ptr;
using std::string;
#include "utils/serializablehelper.h"
#include "bgv.cpp"

namespace lbcrypto {

template<typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl() {
	m_format = EVALUATION;
	m_params.reset(new CRTPolyImpl::Params(0, 1));
	m_vectors.clear();
}

template<typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const shared_ptr<CRTPolyImpl::Params> dcrtParams, Format format,bool initializeElementToZero) {
	m_format = format;
	m_params = dcrtParams;

	size_t vecSize = dcrtParams->GetParams().size();

	for (usint i = 0; i < vecSize; i++) {
		PolyType element(dcrtParams->GetParams()[i], format, initializeElementToZero);
		m_vectors.push_back(std::move(element));
	}
}

template<typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const CRTPolyImpl &element) {
	m_format = element.m_format;
	m_params = element.m_params;

	for (usint i = 0; i < m_params->GetParams().size(); i++) {
		PolyType poly(element.m_vectors[i],m_params->GetParams()[i]);
		m_vectors.push_back(std::move(poly));
	}
}

template<typename VecType>
const CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator=(const PolyLargeType &element) {

	throw std::runtime_error("not implemented");

	return *this;
}

//wrong implementation
template<typename VecType>
const CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator=(const NativePoly &element) {

	throw std::runtime_error("not implemented");

	return *this;
}

template<typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const PolyLargeType &element,	const shared_ptr<CRTPolyImpl::Params> params) {
	throw std::runtime_error("not implemented");
}

template<typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const NativePoly &element,const shared_ptr<CRTPolyImpl::Params> params) {
	throw std::runtime_error("not implemented");
}

template<typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const std::vector<PolyType> &towers) {
	throw std::runtime_error("not implemented");
}

template<typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const DggType& dgg, const shared_ptr<CRTPolyImpl::Params> dcrtParams, Format format) {
	m_format = format;
	m_params = dcrtParams;

	size_t vecSize = dcrtParams->GetParams().size();

	PolyType firstPoly(dgg, m_params->GetParams()[0], COEFFICIENT);

	for (usint i = 0; i < vecSize; i++) {
		auto &crtParam = m_params->GetParams()[i];
		firstPoly.SwitchModulus(crtParam->GetModulus(),	crtParam->GetRootOfUnity());
		m_vectors.push_back(firstPoly);
	}

	if (m_format != COEFFICIENT) {
		SwitchFormat();
	}
}

template<typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(DugType& dug,	const shared_ptr<CRTPolyImpl::Params> dcrtParams, Format format) {

	m_format = format;
	m_params = dcrtParams;

	size_t numberOfTowers = dcrtParams->GetParams().size();

	for (usint i = 0; i < numberOfTowers; i++) {
		PolyType poly(dug, dcrtParams->GetParams()[i], format);
		m_vectors.push_back(std::move(poly));
	}

}

template<typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const BugType& bug, const shared_ptr<CRTPolyImpl::Params> dcrtParams, Format format) {

	m_format = format;
	m_params = dcrtParams;

	size_t numberOfTowers = dcrtParams->GetParams().size();

	PolyType firstPoly(bug, m_params->GetParams()[0], COEFFICIENT);

	for (usint i = 0; i < numberOfTowers; i++) {
		auto &crtParam = m_params->GetParams()[i];
		firstPoly.SwitchModulus(crtParam->GetModulus(),	crtParam->GetRootOfUnity());
		m_vectors.push_back(firstPoly);
	}

	if (m_format != COEFFICIENT) {
		SwitchFormat();
	}

}

template<typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const TugType& tug, const shared_ptr<CRTPolyImpl::Params> dcrtParams, Format format) {

	m_format = format;
	m_params = dcrtParams;

	size_t numberOfTowers = dcrtParams->GetParams().size();

	PolyType firstPoly(tug, m_params->GetParams()[0], COEFFICIENT);

	for (usint i = 0; i < numberOfTowers; i++) {
		auto &crtParam = m_params->GetParams()[i];
		firstPoly.SwitchModulus(crtParam->GetModulus(), crtParam->GetRootOfUnity());
		m_vectors.push_back(firstPoly);
	}

	if (m_format != COEFFICIENT) {
		SwitchFormat();
	}
}

template<typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(CRTPolyImpl &&element) {
	m_format = element.m_format;
	m_vectors = std::move(element.m_vectors);
	m_params = element.m_params;
	element.m_params = nullptr;
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::CloneParametersOnly() const {

	std::cout << "Inside Clone Param only\n\n";

	CRTPolyImpl res;
	res.m_format = this->m_format;
	res.m_params.reset(new CRTPolyImpl::Params(*this->m_params));

	std::cout << res.m_vectors.size() << endl << endl;

	return std::move(res);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::CloneWithNoise(const DiscreteGaussianGeneratorImpl<VecType> &dgg, Format format) const {

	CRTPolyImpl res = CloneParametersOnly();

	VecType randVec = dgg.GenerateVector(m_params->GetRingDimension(), m_params->GetModulus());

	shared_ptr <ILParamsImpl<Integer>> parm(new ILParamsImpl<Integer>(m_params->GetCyclotomicOrder(), m_params->GetModulus(), 1));
	PolyLargeType element(parm);
	element.SetValues(randVec, m_format);

	res = element;

	return std::move(res);
}

template<typename VecType>
CRTPolyImpl<VecType>::~CRTPolyImpl() {
}

template<typename VecType>
const typename CRTPolyImpl<VecType>::PolyType& CRTPolyImpl<VecType>::GetElementAtIndex(usint i) const {
	if (m_vectors.empty())
		throw std::logic_error("DCRTPolyImpl's towers are not initialized.");
	if (i > m_vectors.size() - 1)
		throw std::logic_error("Index: " + std::to_string(i) + " is out of range.");
	return m_vectors[i];
}

template<typename VecType>
usint CRTPolyImpl<VecType>::GetNumOfElements() const {
	return m_vectors.size();
}

template<typename VecType>
const std::vector<typename CRTPolyImpl<VecType>::PolyType>& CRTPolyImpl<VecType>::GetAllElements() const {
	return m_vectors;
}

template<typename VecType>
Format CRTPolyImpl<VecType>::GetFormat() const {
	return m_format;
}

template<typename VecType>
std::vector<CRTPolyImpl<VecType>> CRTPolyImpl<VecType>::BaseDecompose(usint baseBits, bool evalModeAnswer) const {

	PolyLargeType v(CRTInterpolate());

	std::vector<PolyLargeType> bdV = v.BaseDecompose(baseBits, false);

	std::vector<CRTPolyImpl<VecType>> result;

	// populate the result by converting each of the big vectors into a VectorArray
	for (usint i = 0; i < bdV.size(); i++) {
		CRTPolyImpl<VecType> dv(bdV[i], this->GetParams());
		if (evalModeAnswer)
			dv.SwitchFormat();
		result.push_back(std::move(dv));
	}

	return std::move(result);
}

//Incomplete
template<typename VecType>
std::vector<CRTPolyImpl<VecType>> CRTPolyImpl<VecType>::CRTDecompose(uint32_t baseBits) const {
	uint32_t nWindows = 1;

	if (baseBits > 0) {
		uint32_t nBits = m_vectors[0].GetModulus().GetLengthForBase(2);

		nWindows = nBits / baseBits;
		if (nBits % baseBits > 0)
			nWindows++;
	}

	std::vector<CRTPolyType> result(m_vectors.size() * nWindows);

	return std::move(result);
}

template<typename VecType>
PolyImpl<NativeVector>& CRTPolyImpl<VecType>::ElementAtIndex(usint i) {
	return m_vectors[i];
}

//Incomplete
template<typename VecType>
std::vector<CRTPolyImpl<VecType>> CRTPolyImpl<VecType>::PowersOfBase(usint baseBits) const {
	std::vector<CRTPolyImpl<VecType>> result;

	usint nBits = m_params->GetModulus().GetLengthForBase(2);

	usint nWindows = nBits / baseBits;
	if (nBits % baseBits > 0)
		nWindows++;

	result.reserve(nWindows);

	return std::move(result);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::MultiplicativeInverse() const {
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < m_vectors.size(); i++) {
		tmp.m_vectors[i] = m_vectors[i].MultiplicativeInverse();
	}
	return std::move(tmp);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::ModByTwo() const {
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < m_vectors.size(); i++) {
		tmp.m_vectors[i] = m_vectors[i].ModByTwo();
	}
	return std::move(tmp);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Plus(const CRTPolyImpl &element) const {

	if (m_vectors.size() != element.m_vectors.size()) {
		throw std::logic_error("tower size mismatch; cannot add");
	}
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < tmp.m_vectors.size(); i++) {
		tmp.m_vectors[i] += element.GetElementAtIndex(i);
	}
	return std::move(tmp);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Negate() const {
	CRTPolyImpl<VecType> tmp(this->CloneParametersOnly());
	tmp.m_vectors.clear();

	for (usint i = 0; i < this->m_vectors.size(); i++) {
		PolyType poly(this->m_vectors.at(i).Negate());
		tmp.m_vectors.push_back(std::move(poly));
	}

	return std::move(tmp);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Minus(const CRTPolyImpl &element) const {
	if (m_vectors.size() != element.m_vectors.size()) {
		throw std::logic_error("tower size mismatch; cannot subtract");
	}
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < tmp.m_vectors.size(); i++) {
		tmp.m_vectors[i] -= element.GetElementAtIndex(i);
	}
	return std::move(tmp);
}

template<typename VecType>
const CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator+=(const CRTPolyImpl &rhs) {
	for (usint i = 0; i < this->GetNumOfElements(); i++) {
		this->m_vectors[i] += rhs.m_vectors[i];
	}
	return *this;

}

template<typename VecType>
const CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator-=(const CRTPolyImpl &rhs) {
	for (usint i = 0; i < this->GetNumOfElements(); i++) {
		this->m_vectors[i] -= rhs.m_vectors[i];
	}
	return *this;
}

template<typename VecType>
const CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator*=(const CRTPolyImpl &element) {
	for (usint i = 0; i < this->m_vectors.size(); i++) {
		this->m_vectors[i] *= element.m_vectors[i];
	}

	return *this;
}

template<typename VecType>
bool CRTPolyImpl<VecType>::operator==(const CRTPolyImpl &rhs) const {

	if (GetCyclotomicOrder() != rhs.GetCyclotomicOrder())
		return false;

	if (GetModulus() != rhs.GetModulus())
		return false;

	if (m_format != rhs.m_format) {
		return false;
	}

	if (m_vectors.size() != rhs.m_vectors.size()) {
		return false;
	}

	//check if the towers are the same
	else
		return (m_vectors == rhs.GetAllElements());
}

template<typename VecType>
const CRTPolyImpl<VecType> & CRTPolyImpl<VecType>::operator=(const CRTPolyImpl & rhs) {
	if (this != &rhs) {
		m_format = rhs.m_format;
		m_params = rhs.m_params;
		if (m_vectors.size() != rhs.m_vectors.size()) {
			m_vectors.clear();
			for (usint i = 0; i < rhs.m_vectors.size(); i++) {
				m_vectors.push_back(rhs.m_vectors[i]);
			}
		}
		else {
			for (usint i = 0; i < rhs.m_vectors.size(); i++) {
				m_vectors[i] = rhs.m_vectors[i];
			}
		}
	}

	return *this;
}

template<typename VecType>
const CRTPolyImpl<VecType> & CRTPolyImpl<VecType>::operator=(CRTPolyImpl&& rhs) {
	if (this != &rhs) {
		m_vectors = std::move(rhs.m_vectors);
		m_format = std::move(rhs.m_format);
		m_params = std::move(rhs.m_params);
	}
	return *this;
}

template<typename VecType>
CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator=(std::initializer_list<uint64_t> rhs) {

	usint t = m_params->GetParams().size();

	if (m_vectors.size() == 0) {
		for (usint i = 0; i < t; i++) {
			PolyType p(m_params->GetParams()[i],m_format,true);
			p = rhs;
			m_vectors.push_back(std::move(p));
		}
	}
	else{
		for (usint i = 0; i < t; i++) {
			m_vectors[i] = rhs;
		}
	}

	return *this;
}

//not implemented
template<typename VecType>
CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator=(uint64_t val) {
	throw std::runtime_error("not implemented");
	return *this;
}

//not implemented
template<typename VecType>
CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator=(std::vector<int64_t> val) {
	usint t = m_params->GetParams().size();
	if (m_vectors.size() == 0) {
		for (usint i = 0; i < t; i++) {
			PolyType p(m_params->GetParams()[i],m_format,true);
			p = val;
			m_vectors.push_back(std::move(p));
		}
	}
	else{
		for (usint i = 0; i < t; i++) {
			m_vectors[i] = val;
		}
	}

	return *this;
}

template<typename VecType>
CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator=(std::vector<int32_t> val) {
	return *this;
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Plus(const Integer &element) const {
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < tmp.m_vectors.size(); i++) {
		tmp.m_vectors[i] += element.ConvertToInt();
	}
	return std::move(tmp);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Minus(const Integer &element) const {
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < tmp.m_vectors.size(); i++) {
		tmp.m_vectors[i] -= element.ConvertToInt();
	}

	return std::move(tmp);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Times(const CRTPolyImpl & element) const {
	if (m_vectors.size() != element.m_vectors.size()) {
		throw std::logic_error("tower size mismatch; cannot multiply");
	}
	CRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
	for (usint i = 0; i < m_vectors.size(); i++) {
		//ModMul multiplies and performs a mod operation on the results. The mod is the modulus of each tower.
		tmp.m_vectors[i] *= element.m_vectors[i];
	}
	return std::move(tmp);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Times(const Integer &element) const {
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < m_vectors.size(); i++) {
		tmp.m_vectors[i] = tmp.m_vectors[i] * element.ConvertToInt(); // (element % Integer((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
	}
	return std::move(tmp);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Times(const std::vector<NativeInteger> &element) const {
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < m_vectors.size(); i++) {
		tmp.m_vectors[i] *= element[i]; // (element % Integer((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
	}

	return std::move(tmp);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::MultiplyAndRound(const Integer &p, const Integer &q) const {
	std::string errMsg = "Operation not implemented yet";
	throw std::runtime_error(errMsg);
	return *this;
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::DivideAndRound(const Integer &q) const {
	std::string errMsg = "Operation not implemented yet";
	throw std::runtime_error(errMsg);
	return *this;
}

template<typename VecType>
const CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator*=(const Integer &element) {
	for (usint i = 0; i < this->m_vectors.size(); i++) {
		m_vectors.at(i) *=
				(element.Mod(this->m_vectors[i].GetModulus())).ConvertToInt(); //this->m_vectors.at(i) * (element % IntType((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
	}

	return *this;
}

template<typename VecType>
void CRTPolyImpl<VecType>::SetValuesToZero() {
	for (usint i = 0; i < m_vectors.size(); i++) {
		m_vectors[i].SetValuesToZero();
	}
}

//not implemented
template<typename VecType>
void CRTPolyImpl<VecType>::AddILElementOne() {

}

template<typename VecType>
void CRTPolyImpl<VecType>::MakeSparse(const uint32_t &wFactor) {
	for (usint i = 0; i < m_vectors.size(); i++) {
		m_vectors[i].MakeSparse(wFactor);
	}
}

//not implemented
template<typename VecType>
void CRTPolyImpl<VecType>::Decompose() {

}

template<typename VecType>
bool CRTPolyImpl<VecType>::IsEmpty() const {
	for (size_t i = 0; i < m_vectors.size(); i++) {
		if (!m_vectors.at(i).IsEmpty())
			return false;
	}
	return true;
}

template<typename VecType>
void CRTPolyImpl<VecType>::DropLastElement() {
	if (m_vectors.size() == 0) {
		throw std::out_of_range("Last element being removed from empty list");
	}

	m_vectors.resize(m_vectors.size() - 1);
	CRTPolyImpl::Params *newP = new CRTPolyImpl::Params(*m_params);
	newP->PopLastParam();
	m_params.reset(newP);
}

template<typename VecType>
void CRTPolyImpl<VecType>::ModReduce(const Integer &plaintextModulus) {

	if (m_format != Format::EVALUATION) {
		throw std::logic_error(
				"Mod Reduce function expects EVAL Formatted DCRTPolyImpl. It was passed COEFF Formatted DCRTPolyImpl.");
	}
	this->SwitchFormat();

	usint lastTowerIndex = m_vectors.size() - 1;

	PolyType towerT(m_vectors[lastTowerIndex]); //last tower that will be dropped
	PolyType d(towerT);

	//precomputations
	typename PolyType::Integer ptm(plaintextModulus.ConvertToInt());
	typename PolyType::Integer qt(m_vectors[lastTowerIndex].GetModulus());
	typename PolyType::Integer v(qt.ModInverse(ptm));
	typename PolyType::Integer a((v * qt).ModSub(1, ptm * qt));

	// Since only positive values are being used for Discrete gaussian generator, a call to switch modulus needs to be done
	d.SwitchModulus(ptm * qt, d.GetRootOfUnity());
	// FIXME NOT CHANGING ROOT OF UNITY-TODO: What to do with SwitchModulus and is it necessary to pass rootOfUnity

	// Calculating delta, step 2
	PolyType delta(d.Times(a));

	// Calculating d' = c + delta mod q (step 3)
	// no point in going to size() since the last tower's being dropped
	for (usint i = 0; i < m_vectors.size(); i++) {
		PolyType temp(delta);
		temp.SwitchModulus(m_vectors[i].GetModulus(), m_vectors[i].GetRootOfUnity());
		m_vectors[i] += temp;
	}

	DropLastElement();

	std::vector < PolyType::Integer > qtInverseModQi(m_vectors.size());
	for (usint i = 0; i < m_vectors.size(); i++) {
		const PolyType::Integer& mod = m_vectors[i].GetModulus();
		qtInverseModQi[i] = qt.ModInverse(mod);
		m_vectors[i] = qtInverseModQi[i].ConvertToInt() * m_vectors[i];
	}

	SwitchFormat();

}

//not implemented
template<typename VecType>
typename CRTPolyImpl<VecType>::PolyLargeType CRTPolyImpl<VecType>::CRTInterpolate() const {

	if (this->m_format != EVALUATION)
		throw std::runtime_error("towers need to be in EVALUATION domain");

	usint ringDimension = GetRingDimension();
	usint nTowers = m_vectors.size();

	Integer bigModulus(GetModulus()); // q

	auto copy(*this);
	copy.SwitchFormat();

	// Setting the root of unity to ONE as the calculation is expensive and not required.
	auto param = make_shared<typename CRTPolyImpl<VecType>::Params>(GetCyclotomicOrder(), bigModulus, 1);
	typename CRTPolyImpl<VecType>::PolyLargeType result(param, COEFFICIENT,	true);

	std::vector<Integer> bi;
	std::vector<Integer> xi;

	for (usint j = 0; j < nTowers; j++) {
		Integer mod(m_vectors[j].GetModulus().ToString());
		bi.push_back(bigModulus / mod);
		xi.push_back(bi[j].ModInverse(mod));
	}

	for (usint i = 0; i < ringDimension; i++) {
		Integer coeff(0);
		for (usint j = 0; j < nTowers; j++) {
			coeff += bi[j] * xi[j] * copy.m_vectors[j][i];
			coeff = coeff.Mod(bigModulus);
		}
		result[i] = coeff;
	}

	return std::move(result);

}

template<typename VecType>
NativePoly CRTPolyImpl<VecType>::DecryptionCRTInterpolate(
		PlaintextModulus ptm) const {
	return this->CRTInterpolate().DecryptionCRTInterpolate(ptm);
}

template<typename VecType>
void CRTPolyImpl<VecType>::SwitchFormat() {
	if (m_format == COEFFICIENT) {
		m_format = EVALUATION;
	} else {
		m_format = COEFFICIENT;
	}

	for (usint i = 0; i < m_vectors.size(); i++) {
		m_vectors[i].SwitchFormat();
	}
}

//not implemented
template<typename VecType>
void CRTPolyImpl<VecType>::SwitchModulusAtIndex(usint index, const Integer &modulus, const Integer &rootOfUnity) {
	 throw std::runtime_error(" ");
}

template<typename VecType>
bool CRTPolyImpl<VecType>::InverseExists() const {
	for (usint i = 0; i < m_vectors.size(); i++) {
		if (!m_vectors[i].InverseExists())
			return false;
	}
	return true;
}

template<typename VecType>
double CRTPolyImpl<VecType>::Norm() const {
	PolyLargeType poly(CRTInterpolate());
	return poly.Norm();
}

template<typename VecType>
bool CRTPolyImpl<VecType>::Serialize(Serialized* serObj) const {
	return true;
}

//overwritten
template<typename VecType>
bool CRTPolyImpl<VecType>::Deserialize(const Serialized& serObj) {
	return true;
}

template<typename VecType>
std::ostream& operator<<(std::ostream &os, const CRTPolyImpl<VecType> & p)

//TODO: Standardize this printing so it is like other poly's
		{
	os << "---START PRINT DOUBLE CRT-- WITH SIZE" << p.m_vectors.size()	<< std::endl;
	for (usint i = 0; i < p.m_vectors.size(); i++) {
		os << "VECTOR " << i << std::endl;
		os << p.m_vectors[i];
	}
	os << "---END PRINT DOUBLE CRT--" << std::endl;
	return os;
}

template class CRTPolyImpl<BigVector> ;
typedef CRTPolyImpl<BigVector> CRTPoly;
template class LPCryptoParametersBGV<CRTPoly> ;

}
