#ifndef LBCRYPTO_CRYPTO_RGSW_C
#define LBCRYPTO_CRYPTO_RGSW_C

#include "ringgsw.h"

namespace lbcrypto {

LWEForm::LWEForm(const Poly& a, const Poly &b){
	this->a = a;
	this->b = b;
}

LWEForm::LWEForm(Poly &&a, Poly &&b):a(std::move(a)),b(std::move(b)){

}

LWEForm::LWEForm(const shared_ptr<LPCryptoParameters<Poly>> params) {
	const auto paramsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Poly>>(params);
	a = Poly(paramsBGV->GetElementParams(), EVALUATION, true);
	b = Poly(paramsBGV->GetElementParams(), EVALUATION, true);
}

const Poly& LWEForm::GetA() const{
	return this->a;
}

void LWEForm::SetA(const Poly& a){
	this->a = a;
}

void LWEForm::SetA(Poly &&a){
	this->a = std::move(a);
}

const Poly& LWEForm::GetB() const{
	return this->b;
}

void LWEForm::SetB(const Poly& b){
	this->b = b;
}

void LWEForm::SetB(Poly &&b){
	this->b = std::move(b);
}

void LWEForm::SwitchFormat(){
	this->a.SwitchFormat();
	this->b.SwitchFormat();
}

RGSWKey::RGSWKey(const std::shared_ptr<LPCryptoParameters<Poly>> params){
	this->cryptoParams = params;
}

const std::shared_ptr<LPCryptoParameters<Poly>> RGSWKey::GetCryptoParameters() const{
	return this->cryptoParams;
}

RGSWCiphertext::RGSWCiphertext(const shared_ptr<LPCryptoParameters<Poly>> params): RGSWKey(params){

}

const std::vector<LWEForm>& RGSWCiphertext::GetElements() const{
	return this->m_element;
}

void RGSWCiphertext::SwitchFormat(){
	for(usint i=0;i<m_element.size();i++){
		m_element.at(i).SwitchFormat();
	}
}

void RGSWCiphertext::SetElementAtIndex(usint idx, const Poly &valueB, const Poly& valueA){
	auto it = m_element.begin() + idx;
	if(it==m_element.end()){
		m_element.push_back(std::move(LWEForm(valueA,valueB)));
	}
	else{
		m_element.at(idx).SetA(valueA);
		m_element.at(idx).SetB(valueB);
	}
}

void RGSWCiphertext::SetElementAtIndex(usint idx, Poly &&valueB, Poly &&valueA){
	auto it = m_element.begin() + idx;
	if(it==m_element.end()){
		m_element.push_back(std::move(LWEForm(std::move(valueA),std::move(valueB))));
	}
	else{
		m_element.at(idx).SetA(std::move(valueA));
		m_element.at(idx).SetB(std::move(valueB));
	}
}

RGSWPublicKey::RGSWPublicKey(const shared_ptr<LPCryptoParameters<Poly>> params): RGSWKey(params){
	m_elements = std::make_shared < LWEForm > (params);
}

const LWEForm& RGSWPublicKey::GetPublicElements() const {
	return *m_elements;
}

void RGSWPublicKey::SetPublicElements(const Poly &a, const Poly &b) {
	m_elements->SetA(a);
	m_elements->SetB(b);
}

void RGSWPublicKey::SetPublicElements(Poly &&a, Poly &&b) {
	m_elements->SetA(std::move(a));
	m_elements->SetB(std::move(b));
}

RGSWSecretKey::RGSWSecretKey(const shared_ptr<LPCryptoParameters<Poly>> params): RGSWKey(params){
	const auto paramsBGV = std::dynamic_pointer_cast<LPCryptoParametersBGV<Poly>>(params);
	m_sk = std::make_shared <Poly> (paramsBGV->GetElementParams(), COEFFICIENT, true);
}

const Poly& RGSWSecretKey::GetSecretKey(){
	return *this->m_sk;
}
void RGSWSecretKey::SetSecretKey(const Poly& value){
	*this->m_sk = value;
}
void RGSWSecretKey::SetSecretKey(Poly &&value){
	*this->m_sk = std::move(value);
}

RGSWKeyPair::RGSWKeyPair(const shared_ptr<LPCryptoParameters<Poly>> params){
	this->publicKey = std::make_shared<RGSWPublicKey>(params);
	this->secretKey = std::make_shared<RGSWSecretKey>(params);
}

}

#endif


