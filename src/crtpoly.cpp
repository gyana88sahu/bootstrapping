#include "crtpoly.h"
#include <memory>
using std::shared_ptr;
using std::string;
#include "utils/serializablehelper.h"

namespace lbcrypto{

template <typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl()
{
	m_format = EVALUATION;
	m_params.reset(new CRTPolyImpl::Params(0, 1));
}

template <typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const shared_ptr<CRTPolyImpl::Params> dcrtParams, Format format, bool initializeElementToZero)
{
	m_format = format;
	m_params = dcrtParams;

	size_t vecSize = dcrtParams->GetParams().size();
	m_vectors.reserve(vecSize);

	for (usint i = 0; i < vecSize; i++) {
		auto element = make_shared<PolyType>(dcrtParams->GetParams()[i],format,initializeElementToZero);
		m_vectors.push_back(element);
	}
}

template <typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const CRTPolyImpl &element)
{
	m_format = element.m_format;
	m_params = element.m_params;
	//have to copy explicitly coz of pointers
	for (usint i = 0; i < m_params.size(); i++) {
		auto poly = make_shared<PolyType>(*element.m_vectors[i]);
		this->m_vectors.push_back(poly);
	}
}

template <typename VecType>
const CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator=(const PolyLargeType &element)
{

	if( element.GetModulus() > m_params->GetModulus() ) {
		throw std::logic_error("Modulus of element passed to constructor is bigger that DCRT big modulus");
	}

	size_t vecCount = m_params->GetParams().size();
	m_vectors.clear();
	m_vectors.reserve(vecCount);

	// fill up with vectors with the proper moduli
	for(usint i = 0; i < vecCount; i++ ) {
		auto newvec = make_shared<PolyType>(m_params->GetParams()[i], m_format, true);
		m_vectors.push_back(newvec);
	}

	// need big ints out of the little ints for the modulo operations, below
	std::vector<Integer> bigmods;
	bigmods.reserve(vecCount);
	for( usint i = 0; i < vecCount; i++ )
		bigmods.push_back( Integer(m_params->GetParams()[i]->GetModulus().ConvertToInt()) );

	// copy each coefficient mod the new modulus
	for(usint p = 0; p < element.GetLength(); p++ ) {
		for( usint v = 0; v < vecCount; v++ ) {

			Integer tmp = element.at(p) % bigmods[v];
			m_vectors[v]->at(p)= tmp.ConvertToInt();
		}
	}

	return *this;
}

//wrong implementation
template <typename VecType>
const CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator=(const NativePoly &element)
{

	if( element.GetModulus() > m_params->GetModulus() ) {
		throw std::logic_error("Modulus of element passed to constructor is bigger that DCRT big modulus");
	}

	size_t vecCount = m_params->GetParams().size();
	m_vectors.clear();
	m_vectors.reserve(vecCount);

	// fill up with vectors with the proper moduli
	for(usint i = 0; i < vecCount; i++ ) {
		auto newvec = make_shared<PolyType>(m_params->GetParams()[i], m_format, true);
		m_vectors.push_back(newvec);
	}

	// gets moduli
	std::vector<NativeInteger> mods;
	mods.reserve(vecCount);
	for( usint i = 0; i < vecCount; i++ )
		mods.push_back( NativeInteger(m_params->GetParams()[i]->GetModulus().ConvertToInt()) );

//	// copy each coefficient mod the new modulus
//	for(usint p = 0; p < element.GetLength(); p++ ) {
//		for( usint v = 0; v < vecCount; v++ ) {
//			(*m_vectors[v])[p] = element.m_vectors[p]->Mod(mods[v]);
//		}
//	}

	return *this;
}

template <typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const PolyLargeType &element, const shared_ptr<CRTPolyImpl::Params> params)
{

}

template <typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const NativePoly &element, const shared_ptr<CRTPolyImpl::Params> params)
{

}

template <typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const std::vector<PolyType> &towers)
{

}

template <typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const DggType& dgg, const shared_ptr<CRTPolyImpl::Params> dcrtParams, Format format)
{
	m_format = format;
	m_params = dcrtParams;

	size_t vecSize = dcrtParams->GetParams().size();
	m_vectors.reserve(vecSize);

	PolyType firstPoly(dgg, m_params[0], COEFFICIENT);

	for (usint i = 0; i < vecSize; i++) {
		firstPoly.SwitchModulus(m_params->GetModulus(),	m_params->GetRootOfUnity());
		auto poly = make_shared < PolyType > (firstPoly);
		m_vectors.push_back(poly);
	}

	if (m_format != COEFFICIENT) {
		SwitchFormat();
	}

}

template <typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(DugType& dug, const shared_ptr<CRTPolyImpl::Params> dcrtParams, Format format)
{

	m_format = format;
	m_params = dcrtParams;

	size_t numberOfTowers = dcrtParams->GetParams().size();
	m_vectors.reserve(numberOfTowers);

	for (usint i = 0; i < numberOfTowers; i++) {
		auto poly = make_shared < PolyType > (dug, dcrtParams[i], format);
		m_vectors.push_back(poly);
	}

}

template <typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const BugType& bug, const shared_ptr<CRTPolyImpl::Params> dcrtParams, Format format)
{

	m_format = format;
	m_params = dcrtParams;

	size_t numberOfTowers = dcrtParams->GetParams().size();
	m_vectors.reserve(numberOfTowers);

	PolyType firstPoly(bug, m_params[0], COEFFICIENT);

	for (usint i = 0; i < numberOfTowers; i++) {
		firstPoly.SwitchModulus(m_params->GetModulus(),	m_params->GetRootOfUnity());
		auto poly = make_shared < PolyType > (firstPoly);
		m_vectors.push_back(poly);
	}

	if (m_format != COEFFICIENT) {
		SwitchFormat();
	}


}


template<typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const TugType& tug, const shared_ptr<CRTPolyImpl::Params> dcrtParams, Format format)
{

	m_format = format;
	m_params = dcrtParams;

	size_t numberOfTowers = dcrtParams->GetParams().size();
	m_vectors.reserve(numberOfTowers);

	PolyType firstPoly(tug, m_params[0], COEFFICIENT);

	for (usint i = 0; i < numberOfTowers; i++) {
		firstPoly.SwitchModulus(m_params->GetModulus(),	m_params->GetRootOfUnity());
		auto poly = make_shared <PolyType> (firstPoly);
		m_vectors.push_back(poly);
	}

	if (m_format != COEFFICIENT) {
		SwitchFormat();
	}
}

template <typename VecType>
CRTPolyImpl<VecType>::CRTPolyImpl(const CRTPolyImpl &&element)
{
	m_format = element.m_format;
	m_vectors = std::move(element.m_vectors);
	m_params = std::move(element.m_params);
}


template <typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Clone() const {
	return std::move(CRTPolyImpl(*this));
}

template <typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::CloneParametersOnly() const
{

	CRTPolyImpl res(this->m_params, this->m_format);
	return std::move(res);
}

template <typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::CloneWithNoise(const DiscreteGaussianGeneratorImpl<VecType> &dgg, Format format) const
{

	CRTPolyImpl res = CloneParametersOnly();

	VecType randVec = dgg.GenerateVector(m_params->GetRingDimension(), m_params->GetModulus());

	shared_ptr<ILParamsImpl<Integer>> parm( new ILParamsImpl<Integer>(m_params->GetCyclotomicOrder(), m_params->GetModulus(), 1) );
	PolyLargeType element( parm );
	element.SetValues( randVec, m_format );

	res = element;

	return std::move(res);
}

template <typename VecType>
CRTPolyImpl<VecType>::~CRTPolyImpl() {}

template <typename VecType>
const typename CRTPolyImpl<VecType>::PolyType& CRTPolyImpl<VecType>::GetElementAtIndex (usint i) const
{
	if(m_vectors.empty())
		throw std::logic_error("DCRTPolyImpl's towers are not initialized.");
	if(i > m_vectors.size()-1)
		throw std::logic_error("Index: " + std::to_string(i) + " is out of range.");
	return *m_vectors[i];
}

template <typename VecType>
usint CRTPolyImpl<VecType>::GetNumOfElements() const
{
	return m_vectors.size();
}

template <typename VecType>
const std::vector<shared_ptr<typename CRTPolyImpl<VecType>::PolyType>>& CRTPolyImpl<VecType>::GetAllElements() const
{
	return m_vectors;
}


template <typename VecType>
std::vector<CRTPolyImpl<VecType>> CRTPolyImpl<VecType>::BaseDecompose(usint baseBits, bool evalModeAnswer) const
{

	PolyLargeType v( CRTInterpolate() );

	std::vector<PolyLargeType> bdV = v.BaseDecompose(baseBits, false);


	std::vector<CRTPolyImpl<VecType>> result;

	// populate the result by converting each of the big vectors into a VectorArray
	for( usint i=0; i<bdV.size(); i++ ) {
		CRTPolyImpl<VecType> dv(bdV[i], this->GetParams());
		if( evalModeAnswer )
			dv.SwitchFormat();
		result.push_back( std::move(dv) );
	}

	return std::move(result);
}

//Incomplete
template <typename VecType>
std::vector<CRTPolyImpl<VecType>> CRTPolyImpl<VecType>::CRTDecompose(uint32_t baseBits) const{
	uint32_t nWindows = 1;

	if (baseBits > 0) {
		uint32_t nBits = m_vectors[0]->GetModulus().GetLengthForBase(2);

		nWindows = nBits / baseBits;
		if (nBits % baseBits > 0)
			nWindows++;
	}

	std::vector <CRTPolyType> result(m_vectors.size() * nWindows);

	return std::move(result);
}

template <typename VecType>
PolyImpl<NativeVector>& CRTPolyImpl<VecType>::ElementAtIndex(usint i)
{
	return *m_vectors[i];
}

//Incomplete
template <typename VecType>
std::vector<CRTPolyImpl<VecType>> CRTPolyImpl<VecType>::PowersOfBase(usint baseBits) const{
	std::vector <CRTPolyImpl<VecType>> result;

	usint nBits = m_params->GetModulus().GetLengthForBase(2);

	usint nWindows = nBits / baseBits;
	if (nBits % baseBits > 0)
		nWindows++;

	result.reserve(nWindows);

	return std::move(result);
}

template <typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::MultiplicativeInverse() const
{
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < m_vectors.size(); i++) {
		*tmp.m_vectors[i] = m_vectors[i]->MultiplicativeInverse();
	}
	return std::move(tmp);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::ModByTwo() const
{
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < m_vectors.size(); i++) {
		*tmp.m_vectors[i] = m_vectors[i]->ModByTwo();
	}
	return std::move(tmp);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Plus(const CRTPolyImpl &element) const
{
	if( m_vectors.size() != element.m_vectors.size() ) {
		throw std::logic_error("tower size mismatch; cannot add");
	}
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < tmp.m_vectors.size(); i++) {
		*tmp.m_vectors[i] += element.GetElementAtIndex (i);
	}
	return std::move(tmp);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Negate() const
{
	CRTPolyImpl<VecType> tmp(this->CloneParametersOnly());
	tmp.m_vectors.clear();

	for (usint i = 0; i < this->m_vectors.size(); i++) {
		auto poly = make_shared<PolyType>(this->m_vectors.at(i)->Negate());
		tmp.m_vectors.push_back(poly);
	}

	return std::move(tmp);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Minus(const CRTPolyImpl &element) const
{
	if( m_vectors.size() != element.m_vectors.size() ) {
		throw std::logic_error("tower size mismatch; cannot subtract");
	}
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < tmp.m_vectors.size(); i++) {
		*tmp.m_vectors[i] -= element.GetElementAtIndex (i);
	}
	return std::move(tmp);
}

template <typename VecType>
const CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator+=(const CRTPolyImpl &rhs)
{
	for (usint i = 0; i < this->GetNumOfElements(); i++) {
		*this->m_vectors[i] += *rhs.m_vectors[i];
	}
	return *this;

}

template<typename VecType>
const CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator-=(const CRTPolyImpl &rhs)
{
	for (usint i = 0; i < this->GetNumOfElements(); i++) {
		*this->m_vectors.at(i) -= *rhs.m_vectors[i];
	}
	return *this;

}

template<typename VecType>
const CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator*=(const CRTPolyImpl &element)
{
	for (usint i = 0; i < this->m_vectors.size(); i++) {
		*this->m_vectors.at(i) *= *element.m_vectors.at(i);
	}

	return *this;

}

template<typename VecType>
bool CRTPolyImpl<VecType>::operator==(const CRTPolyImpl &rhs) const
{

	if( GetCyclotomicOrder() != rhs.GetCyclotomicOrder() )
		return false;

	if( GetModulus() != rhs.GetModulus() )
		return false;

	if (m_format != rhs.m_format) {
		return false;
	}

	if (m_vectors.size() != rhs.m_vectors.size()) {
		return false;
	}

	//check if the towers are the same
	else return (m_vectors == rhs.GetAllElements());
}

template<typename VecType>
const CRTPolyImpl<VecType> & CRTPolyImpl<VecType>::operator=(const CRTPolyImpl & rhs)
{
	if (this != &rhs) {
		m_format = rhs.m_format;
		m_params = rhs.m_params;
		if (m_vectors.size() != rhs.m_vectors.size()) {
			m_vectors.clear();
			for(usint i=0;i<rhs.m_vectors.size();i++){
				auto poly = make_shared<PolyType>(*rhs.m_vectors[i]);
				m_vectors.push_back(poly);
			}
		}
		else{
			for (usint i = 0; i < rhs.m_vectors.size(); i++) {
				*m_vectors[i] = *rhs.m_vectors[i];
			}
		}
	}

	return *this;
}

template<typename VecType>
const CRTPolyImpl<VecType> & CRTPolyImpl<VecType>::operator=(CRTPolyImpl&& rhs)
{
	if (this != &rhs) {
		m_vectors = std::move(rhs.m_vectors);
		m_format = std::move(rhs.m_format);
		m_params = std::move(rhs.m_params);
	}
	return *this;
}

template<typename VecType>
CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator=(std::initializer_list<uint64_t> rhs)
{
	usint len = rhs.size();
	static PolyType::Integer ZERO(0);
	if(!IsEmpty()) {
		usint vectorLength = this->m_vectors[0]->GetLength();
		for(usint i = 0; i < m_vectors.size(); ++i) { // this loops over each tower
			for(usint j = 0; j < vectorLength; ++j) { // loops within a tower
				if(j<len) {
				  this->m_vectors[i]->at(j)= *(rhs.begin()+j);
				} else {
				  this->m_vectors[i]->at(j)= ZERO;
				}
			}
		}
	} else {
		for(size_t i=0; i<m_vectors.size(); i++) {
			NativeVector temp(m_params->GetRingDimension());
			temp.SetModulus(m_vectors.at(i)->GetModulus());
			temp = rhs;
			m_vectors.at(i)->SetValues(std::move(temp),m_format);
		}

	}
	return *this;
}

//not implemented
template<typename VecType>
CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator=(uint64_t val)
{

	return *this;
}

//not implemented
template<typename VecType>
CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator=(std::vector<int64_t> val)
{
	return *this;
}


template<typename VecType>
CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator=(std::vector<int32_t> val)
{
	return *this;
}

template <typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Plus(const Integer &element) const
{
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < tmp.m_vectors.size(); i++) {
		*tmp.m_vectors[i] += element.ConvertToInt();
	}
	return std::move(tmp);
}

template<typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Minus(const Integer &element) const
{
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < tmp.m_vectors.size(); i++) {
		*tmp.m_vectors[i] -= element.ConvertToInt();
	}

	return std::move(tmp);
}

template<typename VecType>
DCRTPolyImpl<VecType> DCRTPolyImpl<VecType>::Times(const DCRTPolyImpl & element) const
{
	if( m_vectors.size() != element.m_vectors.size() ) {
		throw std::logic_error("tower size mismatch; cannot multiply");
	}
	DCRTPolyImpl<VecType> tmp(*this);

#pragma omp parallel for
	for (usint i = 0; i < m_vectors.size(); i++) {
		//ModMul multiplies and performs a mod operation on the results. The mod is the modulus of each tower.
		tmp.m_vectors[i] *= element.m_vectors[i];
	}
	return std::move(tmp);
}

template <typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Times(const Integer &element) const
{
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < m_vectors.size(); i++) {
		*tmp.m_vectors[i] = *tmp.m_vectors[i] * element.ConvertToInt(); // (element % Integer((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
	}
	return std::move(tmp);
}

template <typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::Times(const std::vector<NativeInteger> &element) const
{
	CRTPolyImpl<VecType> tmp(*this);

	for (usint i = 0; i < m_vectors.size(); i++) {
		*tmp.m_vectors[i] *= element[i]; // (element % Integer((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
	}

	return std::move(tmp);
}

template <typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::MultiplyAndRound(const Integer &p, const Integer &q) const
{
	std::string errMsg = "Operation not implemented yet";
	throw std::runtime_error(errMsg);
	return *this;
}

template <typename VecType>
CRTPolyImpl<VecType> CRTPolyImpl<VecType>::DivideAndRound(const Integer &q) const
{
	std::string errMsg = "Operation not implemented yet";
	throw std::runtime_error(errMsg);
	return *this;
}

template <typename VecType>
const CRTPolyImpl<VecType>& CRTPolyImpl<VecType>::operator*=(const Integer &element)
{
	for (usint i = 0; i < this->m_vectors.size(); i++) {
		*m_vectors.at(i) *= (element.Mod(this->m_vectors[i]->GetModulus())).ConvertToInt(); //this->m_vectors.at(i) * (element % IntType((*m_params)[i]->GetModulus().ConvertToInt())).ConvertToInt();
	}

	return *this;
}

template <typename VecType>
void CRTPolyImpl<VecType>::SetValuesToZero() {
	for (usint i = 0; i < m_vectors.size(); i++) {
		m_vectors[i]->SetValuesToZero();
	}
}

template <typename VecType>
void CRTPolyImpl<VecType>::MakeSparse(const uint32_t &wFactor)
{
	for(usint i = 0; i < m_vectors.size(); i++) {
		m_vectors[i]->MakeSparse(wFactor);
	}
}

//not implemented
template <typename VecType>
void CRTPolyImpl<VecType>::Decompose()
{

}

template <typename VecType>
bool CRTPolyImpl<VecType>::IsEmpty() const
{
	for (size_t i = 0; i < m_vectors.size(); i++) {
		if (!m_vectors.at(i)->IsEmpty())
			return false;
	}
	return true;
}

template <typename VecType>
void CRTPolyImpl<VecType>::DropLastElement()
{
	if (m_vectors.size() == 0) {
		throw std::out_of_range("Last element being removed from empty list");
	}

	m_vectors.resize(m_vectors.size() - 1);
	CRTPolyImpl::Params *newP = new CRTPolyImpl::Params(*m_params);
	newP->PopLastParam();
	m_params.reset(newP);
}

template <typename VecType>
void CRTPolyImpl<VecType>::ModReduce(const Integer &plaintextModulus)
{

}

template <typename VecType>
typename CRTPolyImpl<VecType>::PolyLargeType CRTPolyImpl<VecType>::CRTInterpolate() const
{

	usint ringDimension = GetRingDimension();
	usint nTowers = m_vectors.size();

	Integer bigModulus(GetModulus()); // qT

	// this is the resulting vector of coefficients
	VecType coefficients(ringDimension, bigModulus);

	// this will finally be  V[j]= {Sigma(i = 0 --> t-1) ValueOf M(r,i) * qt/qj *[ (qt/qj)^(-1) mod qj ]}modqt

	// first, precompute qt/qj factors
	vector<Integer> multiplier(nTowers);

	for (usint vi = 0; vi < nTowers; vi++) {
		Integer qj(m_vectors[vi]->GetModulus().ConvertToInt());
		Integer divBy = bigModulus / qj;
		Integer modInv = divBy.ModInverse(qj).Mod(qj);
		multiplier[vi] = divBy * modInv;

	}

	// if the vectors are not in COEFFICIENT form, they need to be, so we will need to make a copy
	// of them and switchformat on them... otherwise we can just use what we have
	const std::vector<PolyType> *vecs = &m_vectors;
	std::vector<PolyType> coeffVecs;
	if (m_format == EVALUATION) {
		for (usint i = 0; i < m_vectors.size(); i++) {
			PolyType vecCopy(m_vectors[i]);
			vecCopy.SetFormat(COEFFICIENT);
			coeffVecs.push_back(std::move(vecCopy));
		}
		vecs = &coeffVecs;
	}

	//Precompute the Barrett mu parameter
	Integer mu = ComputeMu<Integer>(bigModulus);

	// now, compute the values for the vector
	for (usint ri = 0; ri < ringDimension; ri++) {
		coefficients[ri] = 0;
		for (usint vi = 0; vi < nTowers; vi++) {
			coefficients[ri] +=
					(Integer((*vecs)[vi].GetValues()[ri].ConvertToInt())
							* multiplier[vi]);
		}
		coefficients[ri].ModBarrettInPlace(bigModulus, mu);
	}

	// Setting the root of unity to ONE as the calculation is expensive and not required.
	typename CRTPolyImpl<VecType>::PolyLargeType polynomialReconstructed(shared_ptr<ILParamsImpl<Integer>>(new ILParamsImpl<Integer>(GetCyclotomicOrder(), bigModulus,1)));
	polynomialReconstructed.SetValues(coefficients, COEFFICIENT);

	return std::move(polynomialReconstructed);

}

template <typename VecType>
NativePoly CRTPolyImpl<VecType>::DecryptionCRTInterpolate(PlaintextModulus ptm) const {
	return this->CRTInterpolate().DecryptionCRTInterpolate(ptm);
}


template<typename VecType>
void CRTPolyImpl<VecType>::SwitchFormat()
{
	if (m_format == COEFFICIENT) {
		m_format = EVALUATION;
	} else {
		m_format = COEFFICIENT;
	}

	for (usint i = 0; i < m_vectors.size(); i++) {
		m_vectors[i]->SwitchFormat();
	}
}

//not implemented
template<typename VecType>
void CRTPolyImpl<VecType>::SwitchModulusAtIndex(usint index, const Integer &modulus, const Integer &rootOfUnity)
{

}

template <typename VecType>
bool CRTPolyImpl<VecType>::InverseExists() const
{
	for (usint i = 0; i < m_vectors.size(); i++) {
		if (!m_vectors[i]->InverseExists()) return false;
	}
	return true;
}

template <typename VecType>
double CRTPolyImpl<VecType>::Norm() const
{
	PolyLargeType poly(CRTInterpolate());
	return poly.Norm();
}

template <typename VecType>
bool CRTPolyImpl<VecType>::Serialize(Serialized* serObj) const
{
	if (!serObj->IsObject()) {
		serObj->SetObject();
	}

	Serialized obj(rapidjson::kObjectType, &serObj->GetAllocator());
	if (!m_params->Serialize(&obj))
		return false;


	obj.AddMember("Format", std::to_string(this->GetFormat()), serObj->GetAllocator());

	SerializeVector<PolyType>("Vectors", "PolyImpl", this->GetAllElements(), &obj);

	serObj->AddMember("DCRTPolyImpl", obj, serObj->GetAllocator());

	return true;
}

//overwritten
template <typename VecType>
bool CRTPolyImpl<VecType>::Deserialize(const Serialized& serObj)
{
	SerialItem::ConstMemberIterator it = serObj.FindMember("DCRTPolyImpl");

	if( it == serObj.MemberEnd() )
		return false;

	SerialItem::ConstMemberIterator pIt = it->value.FindMember("ILDCRTParams");
	if (pIt == it->value.MemberEnd()) return false;

	Serialized parm(rapidjson::kObjectType);
	parm.AddMember(SerialItem(pIt->name, parm.GetAllocator()), SerialItem(pIt->value, parm.GetAllocator()), parm.GetAllocator());

	shared_ptr<CRTPolyImpl::Params> json_ilParams(new CRTPolyImpl::Params());
	if (!json_ilParams->Deserialize(parm))
		return false;
	m_params = json_ilParams;

	SerialItem::ConstMemberIterator mIt = it->value.FindMember("Format");
	if( mIt == it->value.MemberEnd() ) return false;
	this->m_format = static_cast<Format>(std::stoi(mIt->value.GetString()));

	mIt = it->value.FindMember("Vectors");

	if( mIt == it->value.MemberEnd() ) {
		return false;
	}

	//bool ret = DeserializeVector<PolyType>("Vectors", "PolyImpl", mIt, &this->m_vectors);

	return true;
}

template <typename VecType>
std::ostream& operator<<(std::ostream &os, const CRTPolyImpl<VecType> & p)

//TODO: Standardize this printing so it is like other poly's
		{
	os << "---START PRINT DOUBLE CRT-- WITH SIZE" << p.m_vectors.size() << std::endl;
	for (usint i = 0; i < p.m_vectors.size(); i++) {
		os << "VECTOR " << i << std::endl;
		os << *p.m_vectors[i];
	}
	os << "---END PRINT DOUBLE CRT--" << std::endl;
	return os;
}



}
