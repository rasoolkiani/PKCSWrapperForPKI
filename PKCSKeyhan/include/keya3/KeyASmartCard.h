#pragma once
#include <wtypes.h>
#include "../Common/KeyACommon.h"
class CKeyASmartCard
{
private:
	SW constructorError;
protected:
	void *deviceContext;
	void *RNG;

public: 
	CKeyASmartCard();
	~CKeyASmartCard();
	USHORT Transmit(BYTE *apdu, USHORT apduLength, BYTE *response, USHORT *responseLength);
	USHORT GetReaderInfo(SC_HANDLE handle, SCInfo *info);
	USHORT ListAllModules(BYTE* moduleIndices, BYTE* moduleCount);
	USHORT OpenDevice(BYTE moduleIndex);
	USHORT CloseDevice();
	SW KeepAlive();

	USHORT GetLibVersion(OUT Version *version);
	SW	GetSerialNumber(BYTE *serialNumber, BYTE length);
	SW	GetRemainingMemorySize(BYTE *memorySize, BYTE length);
	SW	GetChallenge(BYTE *challange, BYTE length);
	SW InternalAuthenticate(BYTE* key, BYTE keyLen, BYTE keyReference, BYTE *Challenge, 
		BYTE challengeLength, BYTE algID);
	SW	ExternalAuthenticate(BYTE* userKey, BYTE userKeyLength, BYTE SCKeyRefrence,BYTE algID);
	SW	MutualAuthenticate(BYTE* userKey, BYTE userKeyLength, BYTE SCKeyRefrence, BYTE algID);
	SW	SelectFile(BYTE mode, USHORT *address, BYTE addressLength, FileInfo requestedInfo);
	SW	FileActivation(BYTE mode, USHORT *address, BYTE addressLength, int activate);
	SW	DeleteFile(BYTE mode, USHORT *address, BYTE addressLength);
	SW	TerminateEF(BYTE mode, USHORT *address_name, BYTE address_nameLength);
	SW	TerminateDF(BYTE mode, USHORT *address, BYTE addressLength);
	SW	TerminateCard();
	SW	CreateDirectory(USHORT fid, Sac sac, BYTE *dfName, BYTE dfNamelength);
	SW	CreateBinaryFile(USHORT fid, USHORT fSize, Sac sac);
	SW	CreateRecordFile(USHORT fid, BYTE MRL, BYTE NOR, Sac sac);
	SW	ReadBinary(USHORT offset, BYTE *ResponseData, USHORT length);
	SW	UpdateBinary(USHORT offset, BYTE *writeData, USHORT length);
	SW	ReadRecord(RecordReferenceMode referencingMode, RefrencingQualifier refrencingQualifier, 
		BYTE indexOrID, BYTE *readData, USHORT length);
	SW	UpdateRecord(RecordReferenceMode referencingMode, RefrencingQualifier refrencingQualifier, 
		BYTE indexOrID, BYTE *writeData, USHORT length);
	SW	DirList(USHORT *ResponseData, BYTE length);
	SW	LogOut();
	SW	SERestore(BYTE seID);
	SW	SEStore(BYTE SeID);
	SW	SEErase(BYTE SeID);
	SW	SESet(BYTE *CRTBuffer, BYTE length);
	SW	GenerateKeyPair(BYTE *random, BYTE randomLength, BOOL exportable, ALGORITHM algorithmID, 
						BYTE* publicExponent, BYTE publicExponentLength, BYTE keyReference, 
						USHORT keyPairBitLength, BYTE keepPQ, BYTE* keyPairBuffer, USHORT bufferLength);
	SW  GenerateKey(RecordReferenceMode referencingMode, RefrencingQualifier refrencingQualifier, BYTE index,
		BYTE *seed, USHORT length);

	SW	AccessPublicKey(BYTE keyReference, PublicKey *publicKey);
	SW	Hash(BYTE *inputBuffer, USHORT inputLength, BYTE *hash, BYTE* hashLength);
	SW	ComputeCryptographicChecksum(BYTE *inputBuffer, USHORT inputLength, BYTE *checksum, BYTE* checksumLength);

	SW	Encrypt(BYTE *plainBuffer, USHORT plainLength, BYTE *encryptedBuffer, USHORT* encryptedLength);

	SW	Decrypt(BYTE *encryptedBuffer, USHORT encryptedLength, BYTE *plainBuffer, USHORT* plainLength);
	SW	Sign(BYTE *inputBuffer, USHORT inputLength, BYTE *signature, USHORT* signatureLength);
	SW	VerifySignature(BYTE *plainBuffer, USHORT plainLength, BYTE *signature, USHORT signatureLength);
	SW	VerifyCertificate(KEY_REFERENCE keyReference, char* filePath, BYTE filePathLength, 
		BYTE* password, BYTE passwordLength);
	SW	GetSymKeyInfo(SymmetricKeyInfo *keyInfo);
	SW	GetAsymKeyInfo(AsymmetricKeyInfo *keyInfo);
	SW	ChangeRefData(BYTE PINReference, BYTE *oldPIN, BYTE oldPINLength, BYTE *newPIN, BYTE newPINLength);
	SW	ChangeUnblockRefData(BYTE PINReference, BYTE *oldPIN, BYTE oldPINLength, BYTE *newPIN, BYTE newPINLength);
	SW	VerifyPIN(BYTE PINReference, BYTE *PIN, BYTE PINlength);
	SW	VerifyUnblockPIN(BYTE PINReference, BYTE *PIN, BYTE PINlength);
	SW	GetPINRetryLeft(BYTE PINReference);
	SW	ManageChannel(ManageChanelOperation manageChanelOperation);	
	SW  GetResponse(BYTE* responseBuffer, BYTE length);
	SW  SetSMState(SMState smState);
	SW	GetVersionInfo(VersionInfo* versionInfo);
	SW	SetDFName(BYTE* dfName, BYTE nameLength);
	SW	ResetRetryCounter(BYTE PINReference, BYTE* unblockPIN, BYTE unblockPINLength, BYTE* newPIN, BYTE newPINLength);
	
	SW	ChangeOperationMode(BOOL isApprovedMode);
	SW	GetStatus();
};
