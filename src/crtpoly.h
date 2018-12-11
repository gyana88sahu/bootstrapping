#ifndef CRTPOLY_H
#define CRTPOLY_H


#include "palisade.h"
#include "math/backend.h"
#include "utils/inttypes.h"
#include "utils/exception.h"
#include "lattice/elemparams.h"
#include "lattice/ilparams.h"
#include "lattice/ildcrtparams.h"
#include "lattice/ilelement.h"
#include "lattice/poly.h"
#include "math/nbtheory.h"
#include "math/transfrm.h"
#include "math/distrgen.h"
#include "math/quadfloat.h"


namespace lbcrypto{

template <typename VecType>
class CRTPolyImpl : public ILElement< CRTPolyImpl<VecType>,VecType>
{
public:
	using Integer = typename VecType::Integer;
	using Params = ILDCRTParams<Integer>;

	typedef VecType Vector;

	typedef CRTPolyImpl<VecType> CRTPolyType;
	typedef DiscreteGaussianGeneratorImpl<NativeVector> DggType;
	typedef DiscreteUniformGeneratorImpl<NativeVector> DugType;
	typedef TernaryUniformGeneratorImpl<NativeVector> TugType;
	typedef BinaryUniformGeneratorImpl<NativeVector> BugType;

	// this class contains an array of these:
	using PolyType = PolyImpl<NativeVector>;

	// the composed polynomial type
	typedef PolyImpl<VecType> PolyLargeType;

	static const std::string GetElementName() {
		return "CRTPolyImpl";
	}

	// CONSTRUCTORS

	/**
	 * @brief Constructor that initialized m_format to EVALUATION and calls m_params to nothing
	 */
	CRTPolyImpl();


	CRTPolyImpl(const shared_ptr<Params> params, Format format = EVALUATION, bool initializeElementToZero = false);

	const CRTPolyType& operator=(const PolyLargeType& element);

	const CRTPolyType& operator=(const NativePoly& element);

	CRTPolyImpl(const DggType &dgg, const shared_ptr<Params> params, Format format = EVALUATION);

	CRTPolyImpl(const BugType &bug, const shared_ptr<Params> params, Format format = EVALUATION);

	CRTPolyImpl(const TugType &tug, const shared_ptr<Params> params, Format format = EVALUATION);

	CRTPolyImpl(DugType &dug, const shared_ptr<Params> params, Format format = EVALUATION);

	CRTPolyImpl(const PolyLargeType &element, const shared_ptr<Params> params);

	CRTPolyImpl(const NativePoly &element, const shared_ptr<Params> params);

	CRTPolyImpl(const std::vector<PolyType> &elements);

	inline static function<CRTPolyType()> Allocator(
			const shared_ptr<Params> params, Format format) {
		return [=]() {
			return CRTPolyType(params, format, true);
		};
	}

	inline static function<CRTPolyType()> MakeDiscreteGaussianCoefficientAllocator(
			shared_ptr<Params> params, Format resultFormat, double stddev) {
		return [=]() {
			DggType dgg(stddev);
			CRTPolyType ilvec(dgg, params, COEFFICIENT);
			ilvec.SetFormat(resultFormat);
			return ilvec;
		};
	}

	inline static function<CRTPolyType()> MakeDiscreteUniformAllocator(
			shared_ptr<Params> params, Format format) {
		return [=]() {
			DugType dug;
			return CRTPolyType(dug, params, format);
		};
	}

	CRTPolyImpl(const CRTPolyType &element);

	/**
	 * @brief Move constructor.
	 *
	 * @param &&element DCRTPoly to move from
	 */
	CRTPolyImpl(const CRTPolyType &&element);

	//CLONE OPERATIONS
	CRTPolyType Clone() const;


	CRTPolyType CloneEmpty() const {
		return std::move(CRTPolyImpl());
	}

	/**
	 * @brief Clone method creates a new DCRTPoly and clones only the params. The tower values are empty. The tower values can be filled by another process/function or initializer list.
	 */
	CRTPolyType CloneParametersOnly() const;

	CRTPolyType CloneWithNoise(const DiscreteGaussianGeneratorImpl<VecType> &dgg, Format format = EVALUATION) const;

	~CRTPolyImpl();


	const shared_ptr<Params> GetParams() const {
		return m_params;
	}

	const usint GetCyclotomicOrder() const {
		return m_params->GetCyclotomicOrder();
	}

	/**
	 * @brief returns the element's ring dimension
	 * @return returns the ring dimension of the element.
	 */
	const usint GetRingDimension() const {
		return m_params->GetRingDimension();
	}


	const Integer &GetModulus() const {
		return m_params->GetModulus();
	}

	const Integer &GetRootOfUnity() const {
		static Integer t(0);
		return t;
	}

	usint GetLength() const {
		if (m_vectors.size() == 0)
			return 0;

		return m_vectors[0]->GetValues().GetLength();
	}

	const PolyType &GetElementAtIndex(usint i) const;

	usint GetNumOfElements() const;

	const std::vector<shared_ptr<PolyType>>& GetAllElements() const;

	Format GetFormat() const;

	std::vector<CRTPolyType> BaseDecompose(usint baseBits,	bool evalModeAnswer = true) const;


	std::vector<CRTPolyType> PowersOfBase(usint baseBits) const;

	std::vector<CRTPolyType> CRTDecompose(uint32_t baseBits = 0) const;

	const CRTPolyType& operator=(const CRTPolyType &rhs);

	const CRTPolyType& operator=(CRTPolyType &&rhs);

	CRTPolyType& operator=(std::initializer_list<uint64_t> rhs);

	CRTPolyType& operator=(uint64_t val);

	CRTPolyType& operator=(std::vector<int64_t> rhs);

	CRTPolyType& operator=(std::vector<int32_t> rhs);

	CRTPolyType operator-() const {
		CRTPolyType all0(this->GetParams(), this->GetFormat(), true);
		return all0 - *this;
	}

	bool operator==(const CRTPolyType &rhs) const;

	const CRTPolyType& operator+=(const CRTPolyType &rhs);

	const CRTPolyType& operator-=(const CRTPolyType &rhs);

	CRTPolyType AutomorphismTransform(const usint &i) const {
		CRTPolyType result(*this);
		for (usint k = 0; k < m_vectors.size(); k++) {
			*result.m_vectors[k] = m_vectors[k]->AutomorphismTransform(i);
		}
		return result;
	}

	CRTPolyType Plus(const CRTPolyType &element) const;

	CRTPolyType Times(const CRTPolyType &element) const;

	CRTPolyType Minus(const CRTPolyType &element) const;

	//SCALAR OPERATIONS

	CRTPolyType Plus(const Integer &element) const;

	CRTPolyType Minus(const Integer &element) const;

	CRTPolyType Times(const Integer &element) const;

	CRTPolyType Times(const std::vector<NativeInteger> &element) const;

	CRTPolyType MultiplyAndRound(const Integer &p, const Integer &q) const;

	CRTPolyType DivideAndRound(const Integer &q) const;

	CRTPolyType Negate() const;

	const CRTPolyType& operator+=(const Integer &element) {
		for (usint i = 0; i < this->GetNumOfElements(); i++) {
			*this->m_vectors[i] +=
					(element.Mod(this->m_vectors[i]->GetModulus())).ConvertToInt();
		}
		return *this;
	}

	const CRTPolyType& operator-=(const Integer &element) {
		for (usint i = 0; i < this->GetNumOfElements(); i++) {
			*this->m_vectors[i] -=
					(element.Mod(this->m_vectors[i]->GetModulus())).ConvertToInt();
		}
		return *this;
	}

	const CRTPolyType& operator*=(const Integer &element);

	const CRTPolyType& operator*=(const CRTPolyType &element);

	PolyType& ElementAtIndex(usint i);

	CRTPolyType MultiplicativeInverse() const;

	CRTPolyType ModByTwo() const;

	CRTPolyType Mod(const Integer &modulus) const {
		throw std::logic_error("Mod of an Integer not implemented on DCRTPoly");
	}

	const VecType &GetValues() const {
		throw std::logic_error("GetValues not implemented on DCRTPoly");
	}

	void SetValues(const VecType &values, Format format) {
		throw std::logic_error("SetValues not implemented on DCRTPoly");
	}

	void SetElementAtIndex(usint index, const PolyType &element) {
		m_vectors[index] = element;
	}

	void SetValuesToZero();

	void AddILElementOne();

	CRTPolyType AddRandomNoise(const Integer &modulus) const {
		throw std::logic_error(
				"AddRandomNoise is not currently implemented for DCRTPoly");
	}

	void MakeSparse(const uint32_t &wFactor);

	void Decompose();

	bool IsEmpty() const;

	void DropLastElement();

	void ModReduce(const Integer &plaintextModulus);

	PolyLargeType CRTInterpolate() const;

	PolyType DecryptionCRTInterpolate(PlaintextModulus ptm) const;

	void SwitchFormat();

	void SwitchModulus(const Integer &modulus, const Integer &rootOfUnity, const Integer &modulusArb = Integer(0), const Integer &rootOfUnityArb = Integer(0)) {
		throw std::logic_error("SwitchModulus not implemented on CRTPoly");
	}

	void SwitchModulusAtIndex(usint index, const Integer &modulus, const Integer &rootOfUnity);

	bool InverseExists() const;

	double Norm() const;

	//JSON FACILITY
	bool Serialize(Serialized* serObj) const;

	bool Deserialize(const Serialized& serObj);

	friend inline std::ostream& operator<<(std::ostream& os, const CRTPolyType& vec) {
		for (usint i = 0; i < vec.GetAllElements().size(); i++) {
			if (i != 0)
				os << std::endl;
			os << i << ": ";
			os << vec.GetAllElements()[i];
		}
		return os;
	}

	friend inline CRTPolyType operator+(const CRTPolyType &a, const CRTPolyType &b) {
		return a.Plus(b);
	}

	friend inline CRTPolyType operator+(const CRTPolyType &a, const Integer &b) {
		return a.Plus(b);
	}

	friend inline CRTPolyType operator+(const Integer &a, const CRTPolyType &b) {
		return b.Plus(a);
	}

	friend inline CRTPolyType operator-(const CRTPolyType &a, const CRTPolyType &b) {
		return a.Minus(b);
	}

	friend inline CRTPolyType operator-(const CRTPolyType &a, const Integer &b) {
		return a.Minus(b);
	}

	friend inline CRTPolyType operator*(const CRTPolyType &a, const CRTPolyType &b) {
		return a.Times(b);
	}

	friend inline CRTPolyType operator*(const CRTPolyType &a, const Integer &b) {
		return a.Times(b);
	}

	friend inline CRTPolyType operator*(const Integer &a, const CRTPolyType &b) {
		return b.Times(a);
	}


private:
	shared_ptr<Params> m_params;

	// array of vectors used for double-CRT presentation
	std::vector<std::shared_ptr<PolyType>> m_vectors;

	// Either Format::EVALUATION (0) or Format::COEFFICIENT (1)
	Format m_format;

};

}//namespace ends


#endif
