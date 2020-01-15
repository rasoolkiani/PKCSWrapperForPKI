#pragma once
#include "KeyACommon.h"
#include "TokenDefinitions.h"

namespace KeyA3
{
	class CKeyA3Crypto
	{
	private:
		USHORT parentConstructorError;
		void **devicecontext;
		void *RNG;
	public:
		CKeyA3Crypto(void **devicecontextInit, USHORT parentConstructorErrorInit, void *RNGInit);
		~CKeyA3Crypto(void);
		USHORT Hash(ALGORITHM algorithm, BYTE *inputBuffer, USHORT inputLength, BYTE *hash, BYTE* hashLength);
		USHORT Hmac(KeyType keyType, KEY_REFERENCE keyReference, ALGORITHM algorithm, 
			BYTE *inputBuffer, USHORT inputLength, BYTE *hash, BYTE* hashLength);

		// Symmetric key cryptography
		USHORT SetKey(AccessType accessType, KEY_REFERENCE keyReference, BYTE *key, BYTE length);
		USHORT DeleteKey(AccessType accessType, KEY_REFERENCE keyReference);
		USHORT Encrypt(KeyType keyType, ALGORITHM algorithm, KEY_REFERENCE keyReference, BYTE* iv, IN BYTE ivLength, BYTE *plainBuffer, 
			USHORT plainLength, BYTE *encryptedBuffer, USHORT* encryptedLength);
		USHORT Decrypt(KeyType keyType, ALGORITHM algorithm, KEY_REFERENCE keyReference, BYTE* iv, IN BYTE ivLength, BYTE *encryptedBuffer, 
			USHORT encryptedLength, BYTE *plainBuffer, USHORT* plainLength);

		//Asymmetric key cryptography
		USHORT ImportKeyPair(ASYMMETRIC_KEY_PAIR_REFERENCE keyReference, BOOL Exportable, AsymmetricKey *asymmetricKey);
		USHORT ExportKeyPair(ASYMMETRIC_KEY_PAIR_REFERENCE keyReference, AsymmetricKey *asymmetricKey);
		USHORT GetPublicKey(UserType userType, ASYMMETRIC_KEY_PAIR_REFERENCE keyReference, PublicKey *publicKey);
    	USHORT GetAsymmetricKeyInfo(AsymmetricKeyInfo *keyInfo);
		USHORT DeleteKeyPair(ASYMMETRIC_KEY_PAIR_REFERENCE keyReference);
		USHORT PublicEncrypt(UserType userType, ALGORITHM algorithm, ASYMMETRIC_KEY_PAIR_REFERENCE keyReference, 
			BYTE *plainBuffer, USHORT plainLength, 
			BYTE *encryptedBuffer, USHORT* encryptedLength);
		USHORT PrivateDecrypt(ALGORITHM algorithm, ASYMMETRIC_KEY_PAIR_REFERENCE keyReference, BYTE *encryptedBuffer, 
			USHORT encryptedLength, BYTE *plainBuffer, USHORT* plainLength);
		USHORT Sign(ALGORITHM algorithm, ASYMMETRIC_KEY_PAIR_REFERENCE keyReference, BYTE *inputBuffer, 
			USHORT inputLength, BYTE *signature, USHORT* signatureLength);
		USHORT Verify(UserType userType, ALGORITHM algorithm, ASYMMETRIC_KEY_PAIR_REFERENCE keyReference, 
			BYTE *inputBuffer, USHORT inputLength, BYTE *signature, USHORT signatureLength);

		// Certificate functions:
		USHORT StoreCertificate(CERTIFICATE_REFERENCE certificateReference, BOOL ReStorable, unicode_char* filePath);
		USHORT RetrieveCertificate(UserType userType, CERTIFICATE_REFERENCE certificateReference,  
			BYTE* certificateBuffer, USHORT* certificateBufferLength);
		USHORT DeleteCertificate(CERTIFICATE_REFERENCE certificateReference);
		USHORT ImportCertificate(KEY_REFERENCE keyReference, BOOL Exportable, unicode_char* filePath, char* password);

		//Random Number
		USHORT GetRandomNumber(BYTE* randomNumberBuffer, BYTE randomNumberLength);
		USHORT GenerateKeyPair(BYTE* random, BYTE randomLength, BOOL Exportable, BOOL keepPQ, AsymmetricKey *asymmetricKey, 
			BYTE algorithmID, BYTE* publicExp, BYTE publicExpLength, USHORT keyLen, 
			KEY_REFERENCE keyRefrence, BOOL storeKeyPair);
		USHORT GenerateKey(AccessType accessType, KEY_REFERENCE keyReference, BYTE* random, BYTE randomLength);
	};

}
