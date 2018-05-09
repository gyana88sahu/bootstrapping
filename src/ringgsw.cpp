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

std::vector<LWEForm>& RGSWCiphertext::GetElements(){
	return this->m_element;
}

void RGSWCiphertext::SwitchFormat(){
	for(usint i=0;i<m_element.size();i++){
		m_element.at(i).SwitchFormat();
	}
}

void RGSWCiphertext::SetElementAtIndex(usint idx, const Poly &valueA, const Poly& valueB){
	auto it = m_element.begin() + idx;
	if(it==m_element.end()){
		m_element.push_back(std::move(LWEForm(valueA,valueB)));
	}
	else{
		m_element.at(idx).SetA(valueA);
		m_element.at(idx).SetB(valueB);
	}
}

void RGSWCiphertext::SetElementAtIndex(usint idx, Poly &&valueA, Poly &&valueB){
	auto it = m_element.begin() + idx;
	if(it==m_element.end()){
		m_element.push_back(std::move(LWEForm(std::move(valueA),std::move(valueB))));
	}
	else{
		m_element.at(idx).SetA(std::move(valueA));
		m_element.at(idx).SetB(std::move(valueB));
	}
}

const std::vector<LWEForm>& RGSWPublicKey::GetPublicElements() const{
	return this->m_elements;
}

const Poly& RGSWPublicKey::GetAPublicElementsAtIndex(usint idx) const{
	return this->m_elements.at(idx).GetA();
}

const Poly& RGSWPublicKey::GetBPublicElementsAtIndex(usint idx) const{
	return this->m_elements.at(idx).GetB();
}

void RGSWPublicKey::SetAPublicElementAtIndex(usint idx, const Poly& value){//use only when element exist at that idx
	m_elements.at(idx).SetA(value);
}

void RGSWPublicKey::SetAPublicElementAtIndex(usint idx, Poly &&value){
	m_elements.at(idx).SetA(std::move(value));
}

void RGSWPublicKey::SetBPublicElementAtIndex(usint idx, const Poly& value){
	m_elements.at(idx).SetB(value);
}

void RGSWPublicKey::SetBPublicElementAtIndex(usint idx, Poly &&value){
	m_elements.at(idx).SetB(std::move(value));
}

void RGSWPublicKey::SetPublicElementAtIndex(usint idx, const Poly &valueA, const Poly &valueB){
	auto it = m_elements.begin()+idx;
	if(it==m_elements.end()){
		m_elements.push_back(std::move(LWEForm(valueA,valueB)));
	}
	else{
		m_elements.at(idx).SetA(valueA);
		m_elements.at(idx).SetB(valueB);
	}
}

void RGSWPublicKey::SetPublicElementAtIndex(usint idx, Poly &&valueA, Poly &&valueB){
	auto it = m_elements.begin()+idx;
	if(it==m_elements.end()){
		m_elements.push_back(std::move(LWEForm(std::move(valueA),std::move(valueB))));
	}
	else{
		m_elements.at(idx).SetA(std::move(valueA));
		m_elements.at(idx).SetB(std::move(valueB));
	}
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

RGSWKeyPair::RGSWKeyPair(const shared_ptr<LPCryptoParametersRLWE<Poly>> params){
	this->publicKey = std::make_shared<RGSWPublicKey>(params);
	this->secretKey = std::make_shared<RGSWSecretKey>(params);
}

}

#endif


