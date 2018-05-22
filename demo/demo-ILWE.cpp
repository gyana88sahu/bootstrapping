#include "../src/ILWEOps.h"
#include "../src/integerlwedefs.h"

using namespace lbcrypto;
using namespace std;

int main(int argc, char *argv[]){

	NativeInteger q(5915587277);
	NativeInteger p(4);
	usint dim = 500;

	auto dgg = make_shared<NativePoly::DggType>(4.0);
	auto dug = make_shared<NativePoly::DugType>();
	dug->SetModulus(q);

	shared_ptr<ILWEParams> params = make_shared<ILWEParams>(p,q,dim);

	params->SetDiscreteUniformGenerator(dug);
	params->SetDiscreteGaussianGenerator(dgg);

	auto kp = ILWEOps::KeyGen(params);

	auto cipher = ILWEOps::Encrypt(*kp.publickey, 1);

	usint message = ILWEOps::Decrypt(cipher, *kp.secretkey);

	cout << message<<endl;

	return 0;
}




