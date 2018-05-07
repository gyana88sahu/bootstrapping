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

std::vector<LWEForm>& RGSWCiphertext::GetElements(){
	return this->m_element;
}

void RGSWCiphertext::SwitchFormat(){
	for(usint i=0;i<m_element.size();i++){
		m_element.at(i).SwitchFormat();
	}
}

RGSWKey::RGSWKey(const std::shared_ptr<LPCryptoParameters<Poly>> params){
	this->cryptoParams = params;
}

const std::shared_ptr<LPCryptoParameters<Poly>> RGSWKey::GetCryptoParameters() const{
	return this->cryptoParams;
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

void RGSWPublicKey::SetAPublicElementAtIndex(usint idx, const Poly& value){
	this->m_elements.at(idx).SetA(value);
}

void RGSWPublicKey::SetAPublicElementAtIndex(usint idx, Poly &&value){
	this->m_elements.at(idx).SetA(std::move(value));
}

void RGSWPublicKey::SetAPublicElement(const std::vector<Poly> &values){
	for(usint i=0;i<values.size();i++){
		this->m_elements.at(i).SetA(values.at(i));
	}
}

void RGSWPublicKey::SetAPublicElement(std::vector<Poly> &&values){
	for(usint i=0;i<values.size();i++){
		this->m_elements.at(i).SetA(std::move(values.at(i)));
	}
}

void RGSWPublicKey::SetBPublicElementAtIndex(usint idx, const Poly& value){
	this->m_elements.at(idx).SetB(value);
}

void RGSWPublicKey::SetBPublicElementAtIndex(usint idx, Poly &&value){
	this->m_elements.at(idx).SetB(std::move(value));
}

void RGSWPublicKey::SetBPublicElement(const std::vector<Poly> &values){
	for(usint i=0;i<values.size();i++){
		this->m_elements.at(i).SetB(values.at(i));
	}
}

void RGSWPublicKey::SetBPublicElement(std::vector<Poly> &&values){
	for(usint i=0;i<values.size();i++){
		this->m_elements.at(i).SetB(std::move(values.at(i)));
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


