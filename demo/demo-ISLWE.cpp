#include "../src/ISLWE.h"
#include "../src/integerlwedefs.h"

using namespace lbcrypto;
using namespace std;

void runEncryptDecrypt(usint m);

int main(int argc, char *argv[]){

	usint m = 4;
	runEncryptDecrypt(m);


	return 0;
}

void runEncryptDecrypt(usint m){
	NativeInteger q(512);
	NativeInteger p(5);
	usint dim = 500;

	auto dgg = make_shared<NativePoly::DggType>(2.0);
	auto dug = make_shared<NativePoly::DugType>();
	dug->SetModulus(q);

	//cout<<dgg->GenerateVector(dim,q);

	shared_ptr<ILWEParams> params = make_shared<ILWEParams>(p,q,dim);

	params->SetDiscreteUniformGenerator(dug);
	params->SetDiscreteGaussianGenerator(dgg);

	auto kp = ISLWEOps::KeyGen(params);

	auto cipher = ISLWEOps::Encrypt(*kp.publickey, m);

	usint message = ISLWEOps::Decrypt(cipher, *kp.secretkey);

	cout << message << "\t";
}



