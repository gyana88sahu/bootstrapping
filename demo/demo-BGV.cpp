#include "palisade.h"
#include "../src/ILWEOps.h"
#include "../src/integerlwedefs.h"
#include "cryptocontext.h"
#include "../src/BGV.h"
#include <numeric>
#include <functional>

using namespace lbcrypto;
using namespace std;

Plaintext GetEncoding(const CryptoContext<Poly> &cc,usint message, usint q);

vector<Ciphertext<Poly>> GenerateBootstrappingKey(const NativeVector &nv, const CryptoContext<Poly> cc,const LPPublicKey<Poly> pk);

CryptoContext<Poly> GetBGVCryptoContext();
Plaintext GetEncoding(const CryptoContext<Poly> &cc,NativeInteger message, NativeInteger q);


void runBootstrappingExperiment(usint m1, usint m2);


int main(int argc, char *argv[]){

	runBootstrappingExperiment(1,0);

	return 0;

}

Plaintext GetEncoding(const CryptoContext<Poly> &cc,usint message, usint q){
	//message is in Zq
	usint m = cc->GetCyclotomicOrder();
	usint N = m / 2; //ring dimension

	std::vector<int64_t> ringVector(N, 0);

	usint idx = (m/q)*message; //idx is between 0 to 2N-1

	if(idx>N-1){
		idx = idx%N;
		ringVector[idx] = -1;
	}
	else{
		ringVector[idx] = 1;
	}

	auto result = cc->MakeCoefPackedPlaintext(ringVector);

	return result;
}

Plaintext GetEncoding(const CryptoContext<Poly> &cc,NativeInteger message, NativeInteger q){
	//message is in Zq
	return GetEncoding(cc, message.ConvertToInt(), q.ConvertToInt());
}

CryptoContext<Poly> GetBGVCryptoContext(){
	usint m = 512;
	usint p = 3;
	BigInteger modulusP(p);
	BigInteger modulusQ("1329227995784915872903807060280359937");
	BigInteger rootOfUnity("1325729462510870192332240459492533043");

	float stdDev = 4;
	shared_ptr<ILParams> params(new ILParams(m, modulusQ, rootOfUnity));

	CryptoContext<Poly> cc = CryptoContextFactory<Poly>::genCryptoContextBGV(params, p, 11, stdDev);

	cc->Enable(ENCRYPTION);
	cc->Enable(SHE);

	return cc;
}

vector<Ciphertext<Poly>> GenerateBootstrappingKey(const NativeVector &nv, const CryptoContext<Poly> cc,
		const LPPublicKey<Poly> pk){

	vector<Ciphertext<Poly>> result;

	NativeVector as(nv);
	auto q = as.GetModulus();
	//Negate as vector
	for (usint i = 0; i < as.GetLength(); i++) {
		as[i] = q.ModSub(as[i], q);
		auto encoding = GetEncoding(cc, as[i], q);
		auto cipher = cc->Encrypt(pk, encoding);
		result.push_back(cipher);
	}

	return result;
}

void runBootstrappingExperiment(usint m1, usint m2){
	NativeInteger q(512);
	NativeInteger p(5);
	usint dim = 5;

	auto dgg = make_shared<NativePoly::DggType>(2.0);
	auto dug = make_shared<NativePoly::DugType>();
	dug->SetModulus(q);

	shared_ptr<ILWEParams> params = make_shared<ILWEParams>(p,q,dim);

	params->SetDiscreteUniformGenerator(dug);
	params->SetDiscreteGaussianGenerator(dgg);

	auto kp = ILWEOps::KeyGen(params);

	cout << "operand 1 is: " << m1 << '\n';
	cout << "operand 2 is: " << m2 << '\n';

	cout << "Encrypting Operand 1\n";
	auto cipher1 = ILWEOps::Encrypt(*kp.publickey, m1);

	cout << "Encrypting Operand 2\n";
	auto cipher2 = ILWEOps::Encrypt(*kp.publickey, m2);

	cout << "Running HomNand Operation\n";
	auto cipherNAND = ILWEOps::EvalNand(cipher1,cipher2);


	auto cc = GetBGVCryptoContext();

	// Initialize the public key containers.
	LPKeyPair<Poly> kpBGV = cc->KeyGen();

	cc->EvalMultKeyGen(kpBGV.secretKey);

	/*cout << cipherNAND->GetA() << '\n';
	cout << cipherNAND->GetB() << '\n';
	cout << kp.secretkey->GetSKElement() << '\n';*/

	auto as(cipherNAND->GetA()*kp.secretkey->GetSKElement());
	auto b = cipherNAND->GetB();
	b += q/4;
	b = b.Mod(q);

	//cout << "b + q/4 is: " << b << '\n';

	//bCipher is the ACCUMULATOR
	auto bEncoding = GetEncoding(cc,b,q);
	auto bCipher = cc->Encrypt(kpBGV.publicKey, bEncoding);


	Plaintext result;

	auto bootKey = GenerateBootstrappingKey(as, cc, kpBGV.publicKey);

	for (auto i : bootKey) {
		bCipher = cc->EvalMult(bCipher, i);
		/*cc->Decrypt(kpBGV.secretKey, bCipher, &result);
		cout << result << '\n'<<'\n';*/
	}

	cc->Decrypt(kpBGV.secretKey, bCipher, &result);

	//cout << result << '\n'<<'\n';

	const auto nv = result->GetCoefPackedValue();

	int sum = std::accumulate(nv.begin(),nv.end(),0);

	cout << "The bit refreshed/bootstarpped  is " << (1-sum)/2 <<'\n';

}
