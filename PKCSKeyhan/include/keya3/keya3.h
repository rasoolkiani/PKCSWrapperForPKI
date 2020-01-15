#pragma once

#include <wtypes.h>
#include "KeyA3Crypto.h"

namespace KeyA3
{
	class CKeyA
	{
	private:
		USHORT constructorError;
	protected:
		void *deviceContext;
		void *RNG;
	public:
		CKeyA3Crypto *KeyACrypto;


	public: 
		CKeyA();
		~CKeyA();
		USHORT GetModuleCount(BYTE *moduleCount);
		USHORT GetSerialNumber(BYTE *serialNumber, BYTE length);
		USHORT GetRemainingMemorySize(BYTE *memorySize, BYTE length);
		USHORT GetModuleInfo(ModuleInfo *info);
		USHORT SetModuleName(BYTE *name, BYTE length);
		USHORT GetModuleName(BYTE *name, BYTE* length);
		USHORT OpenDevice(BYTE moduleIndex, ChannelType val, UserType userType, 
						  BYTE* userKey = NULL, BYTE userKeyLength = 0, BYTE algID = 0);
		USHORT CloseDevice();
		USHORT ListAllModules(BYTE* moduleIndices,BYTE* moduleCount);
		USHORT GetMemoryVolumes(MemoryVolumes *memoryVolumes);
		USHORT GetSymmetricKeyCount(SymKeyCount *symKeyCount);
		USHORT ReadMemory(MemoryType memoryType, USHORT offset, BYTE *buffer, USHORT length);
		USHORT WriteMemory(MemoryType memoryType, USHORT offset, BYTE *buffer, USHORT length);
		USHORT ChangePIN(UserType userType, char* oldPIN, char* newPIN);
		USHORT ChangeUnblockPIN(UserType userType, char* oldPIN, char* newPIN);
		USHORT ResetRetryCounter(UserType userType, char* unblockPIN, char* newPIN);
		USHORT LogIn(UserType userType, char* PIN);
        USHORT GetPINRetryLeft(UserType userType, BYTE *PINRetryLeft);
		USHORT LogOut();
		USHORT StartSecureMessaging(UserType userType, BYTE* userKey, BYTE userKeyLength, BYTE algID);
		USHORT StopSecureMessaging();
		
		const unicode_char* GetErrorText(USHORT errorCode);
		USHORT GetLibVersion(Version *version);
		USHORT SetAttachCallback(KeyA3CallBackProc pCallback, void *params);
        USHORT SetDetachCallback(KeyA3CallBackProc pCallback, void *params);
    	USHORT ChangeOperationMode(BOOL isApprovedMode);
    	USHORT GetStatus(BOOL* isApprovedMode, BOOL* isSelfTestPassed);
	};
}
