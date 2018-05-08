
#include "../src/RingGSWOPS.h"

using namespace std;
using namespace lbcrypto;

int main(int argc, char *argv[]) {

	float stdDev = 4;
	usint relinWindow = 1;

	usint m = 8;
	BigInteger modulus("2199023288321");
	usint plaintextmodulus(5);
	BigInteger rootOfUnity;

	modulus = NextPrime(modulus, m);
	rootOfUnity = RootOfUnity(m, modulus);

	cout << modulus << '\n';
	cout << rootOfUnity << '\n';

	auto ep = make_shared < ILParams > (m, modulus, rootOfUnity);

	auto params = make_shared<LPCryptoParametersBGV<Poly>> (ep, plaintextmodulus, stdDev, 9, 1.006, relinWindow, RLWE, 1);

	RGSWKeyPair kp = RGSWOps::KeyGen(params);

	Poly message(ep, COEFFICIENT);

	message = {1,1,1,1};

	auto cipher = RGSWOps::Encrypt(*kp.publicKey, message);

	auto decryptResult = RGSWOps::Decrypt(cipher, kp.secretKey);

	std::cout << decryptResult << '\n';

	return 0;
}

