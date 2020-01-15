#ifndef KEYA_COMMON_H
#define KEYA_COMMON_H
#include "os_wrapper.h"
#ifndef CALLBACK
#define CALLBACK __stdcall
#endif

#define KEY_REFERENCE								BYTE
#define ASYMMETRIC_KEY_PAIR_REFERENCE				BYTE
#define CERTIFICATE_REFERENCE						BYTE
#define ALGORITHM									BYTE

// Defined values:
#define KEYA_SERIAL_NUMBER_LENGTH					8
#define MAX_ERROR_TEXT_LENGTH						512
#define MAX_ERROR_COUNT								512
#define INFO_FILE_MRL								6
#define MAX_MODULE_COUNTS							0x80
#define MAX_MODULE_NAME								16 //Used in set or get module name
#define MAX_DFNAME									16
#define CHALLENGE_LENGTH							8
#define MAXIMUM_KEY_LENGTH							64
#define MAXIMUM_RSA_LENGTH							512
#define MAXIMUM_RSA_E_BYTES							4

#define MAXIMUM_KEY_RECORD_LENGTH					MAXIMUM_KEY_LENGTH
#define PRIVATE_KEY_REFERENCE						0xFE //Asymmetric key
#define PUBLIC_KEY_REFERENCE						0x01 //Asymmetric key
#define MAX_COMMAND_DATAFIELD_LENGTH				2048
#define MAX_RNG_SEED_LENGTH							48
#define MAX_MEMORY_OFFSET							0x7FFF
#define MAX_BLOCK_LEN								64
#define UNKNOWN_ERROR_CODE							0xffff

//KeyA model
#define BUSINESS_SECURITY							2
#define ADVANCED_SECURITY							3

#define MEM_TYPE_1									1
#define MEM_TYPE_1_SIZE								64

#define MEM_TYPE_2									2
#define MEM_TYPE_2_SIZE								128

#define MEM_TYPE_3									3
#define MEM_TYPE_3_SIZE								256

//OS Status word
#define OS_OK_MORE_INFO								0x6100
#define OS_WARN_MEM_UNCHANGED						0x6200
#define OS_WARN_MEM_CHANGED							0x6300
#define OS_ERR_MEM_UNCHANGED						0x6400
#define OS_ERR_MEM_CHANGED							0x6500
#define OS_COMMAND_NOT_ALLOWED						0x6900
#define OS_WRONG_P1_P2_A							0x6A00
#define OS_WRONG_P1_P2_B							0x6B00
#define OS_WRONG_LE									0x6C00
#define OS_INS_NOT_SUPPORTED						0x6D00
#define OS_CLA_NOT_SUPPORTED						0x6E00
#define OS_WRONG_LENGTH								0x6700
#define OS_NO_PRECISE_DIAGNOSIS						0x6f00

#define OS_WRONG_PARAMETER_IN_DATA					0x6A80	
#define OS_FUNCTION_NOT_SUPPORTED					0x6A81	
#define OS_FILE_NOT_FOUND							0x6A82	
#define OS_RECORD_NOT_FOUND							0x6A83	
#define OS_NOT_ENOUGH_MEMORY						0x6A84	
#define OS_INCORRECT_P1_P2							0x6A86	
#define OS_INCONSISTENT_LC							0x6A87	
#define OS_REF_DATA_NOT_FOUND						0x6A88	
#define OS_FILE_EXISTS								0x6A89	
#define OS_NAME_EXISTS								0x6A8A	

#define OS_REF_DATA_INVALID							0x6964	
#define OS_FILE_IS_INCOMPATIBLE						0x6981	
#define OS_SECURITY_NOT_SATISFIED					0x6982	
#define OS_AUTH_METHOD_BLOCKED						0x6983	
#define OS_REF_DATA_NOT_USABLE						0x6984	
#define	OS_CONDITION_NOT_SATISFIED					0X6985	
#define	OS_NO_CURRENT_EF							0X6986	

#define OS_EOF_REACHED								0x6282	
#define OS_FILE_IS_DEACTIVATED						0x6283	
#define OS_WRONG_FCP_FORMAT							0x6284	
#define OS_FILE_IS_TERMINATED						0x6285	
#define OS_MEMORY_FAILURE							0x6381	
#define OS_FILE_SYSTEM_CORRUPTED					0x6f01	

// Lib Errors:
#define LIB_ERROR									0x1000
#define ERROR_INPUT_LENGTH							0x1000
#define ERROR_INPUT_VALUE							0x1001
#define ERROR_IS_ADDMINLESS							0x1002
#define ERROR_UNKNOWN								0x1003
#define ERROR_MANAGE_CHANNEL_FAIL					0x1004
#define ERROR_DEVICECONTEXT_NULL					0x1005
#define ERROR_MODULEINDEX_WRONG						0x1006
#define ERROR_MODULE_NOT_EXIST						0x1007
#define ERROR_DEVICE_IS_CLOSE						0x1008
#define ERROR_DEVICECONTEXT_INVALID					0x1009
#define ERROR_LIBRARY_NOT_READY						0x100B
#define ERROR_TOO_MANY_DEVICES						0x100C
#define ERROR_CATASTROPHIC_FAILURE					0x100D
#define ERROR_TOO_MANY_CONTEXTS						0x100E
#define ERROR_TRANSMIT_FAILED						0x100F
#define ERROR_OPEN_DEVICE_FAILED					0x1010
#define ERROR_WRONG_INPUT_BUFFER_LENGTH				0x1011
#define ERROR_MODULE_NOT_INITIALIZE					0x1012
#define ERROR_ILLEGAL_ACCESS						0x1013
#define ERROR_WRONG_KEY_LENGTH						0x1014
#define ERROR_PADDING_FAIL							0x1015
#define ERROR_CERTIFICATE_EXTENSION_NOTSUPPORTED	0x1016
#define ERROR_CERTIFICATE_PARSE_FAIL				0x1017
#define ERROR_KEYPAIR_ELEMENTS_INCOMPLETE			0x1018
#define ERROR_PAYA2_FAIL							0x1019
#define ERROR_ASYMMETRIC_ODD_REFRENCE_IS_WRONG		0x101A
#define ERROR_CERTIFICATE_ODD_REFRENCE_IS_WRONG		0x101B
#define ERROR_WRONG_REFRENCE						0x101C
#define ERROR_INTERNALAUTHENTICATION_FAIL			0x101D
#define ERROR_FUNCTIONSPARAMETR_IS_WRONG			0x101E
#define ERROR_MODULE_NOT_RESPONSE					0x101F
#define ERROR_WRONG_IV_LENGTH						0x1020
#define ERROR_CLOSEDEVICE_FAIL						0x1021
#define ERROR_STOPSECUREMESSAGING_FAIL				0x1022
#define ERROR_ILLEGAL_FILESIZE						0x1023
#define ERROR_STORECERTIFICATE_FAIL					0x1024
#define ERROR_UNPACKNOTUSABLE						0x1025
#define ERROR_LC_IS_TOOBIG							0X1026
#define ERROR_REQUESTED_OFFSET_IS_TOOBIG			0X1027

#define ERROR_MUTUALAUTH_FAILED						0x1028
#define ERROR_SM_IS_STOPPED							0x1029

// Lib Errors:TLV Tag
#define ERROR_TLVTAG_ALGID							0x102A
#define ERROR_TLVTAG_KEYLEN							0x102B
#define ERROR_TLVTAG_PUBEXP							0x102C
#define ERROR_TLVTAG_MODULUS						0x102D
#define ERROR_TLVTAG_PRIVKEY						0x102E
#define ERROR_TLVTAG_PQ								0x102F
#define ERROR_SHAREDFILE_NOTEXIST					0x1030
#define ERROR_INVALID_CASE							0x1031
#define ERROR_INITIALIZATION_FAILED_INIT_SEM		0x1032
#define ERROR_INITIALIZATION_FAILED_INIT_WAIT		0x1033
#define ERROR_INITIALIZATION_FAILED_TRANS_SEM		0x1034
#define ERROR_INITIALIZATION_FAILED_TOKEN_SEM		0x1035
#define ERROR_INITIALIZATION_FAILED_ATTACH_SEM		0x1036
#define ERROR_INITIALIZATION_FAILED_NOTIFICATION	0x1037
#define ERROR_RELEASESEMAPHORE_FAILED				0x1038
#define ERROR_TRANSMITSEMAPHORE_NOTEXIST			0x1039
#define ERROR_TOKENSEMAPHORE_NOTEXIST				0x103A
#define ERROR_MODULE_ISNOT_OPEN						0x103B
#define ERROR_INVALID_ASYMMETRIC_KEY                0x103C
#define ERROR_RNG_FAILED			                0x103D

#define SUCCESS										0x0000
#define RET_CODE_SUCCESS							0x9000
#define RET_CODE_LOW_RANDOMNESS						0x6F02
#define COMPLETE_OP_WITH_EXTRA_INFO					0x61

typedef struct _KeyA3CallbackParams
{
	BYTE moduleIndex;
	void *param;
}KeyA3CallbackParams;

typedef ThreadResult (CALLBACK* KeyA3CallBackProc)(KeyA3CallbackParams *params);

typedef union _SW
{
	struct _sw
	{
		BYTE sw2;
		BYTE sw1;
	} sw;
	USHORT retCode;
} SW;

#pragma pack(push, 2)

typedef struct _Version 
{
	BYTE major;
	BYTE minor;
	BYTE state;
	USHORT build;
} Version;

typedef struct _VersionInfo
{
	Version OSVersion;
	Version hardwareVersion;
}VersionInfo;
#pragma pack(pop)

typedef struct _PublicKey
{
	USHORT bitLen;
	BYTE n[MAXIMUM_RSA_LENGTH];
	BYTE e[MAXIMUM_RSA_E_BYTES];
} PublicKey;

typedef struct _RSAKeyPair
{
	BOOL hasPrivateKey;
	USHORT bitLen;
	BYTE n[MAXIMUM_RSA_LENGTH];
	BYTE e[MAXIMUM_RSA_E_BYTES];
	BYTE d[MAXIMUM_RSA_LENGTH];
} RSAKeyPair;

typedef union _KeyContext
{
	RSAKeyPair RSA;
}KeyContext;

typedef struct _AsymmetricKey
{
	BYTE algID;
	KeyContext context;
} AsymmetricKey;

typedef struct _Certificate
{
	BYTE *cert;
} Certificate;

typedef struct _SymmetricKeyInfo
{
	KEY_REFERENCE keyReference;
	BYTE keyLength;
	ALGORITHM defaultAlgorithm;
} SymmetricKeyInfo;

typedef struct _AsymmetricKeyInfo
{
	ASYMMETRIC_KEY_PAIR_REFERENCE keyReference;
	BYTE keyLength;
	ALGORITHM algorithm;
} AsymmetricKeyInfo;

typedef struct _ModuleInfo
{
	Version		hardwareVersion;
	Version		OSVersion;
	BYTE		model;
	USHORT		memorySize;
	struct SupportedAlgorithms
	{
		DWORD	DES : 1;
		DWORD	DES3 : 1;
		DWORD	AES_128 : 1;
		DWORD	AES_192 : 1;

		DWORD	AES_256 : 1;
		DWORD	PAYA2 : 1;
		DWORD	HMAC_SHA1 : 1;
		DWORD	HMAC_MD5 : 1;

		DWORD	HASH_SHA1 : 1;
		DWORD	HASH_SHA256 : 1;
		DWORD	HASH_MD5 : 1;
		DWORD	HASH_CRC32 : 1;

		DWORD	RSA_512 : 1;
		DWORD	RSA_1024 : 1;
		DWORD	RSA_2048 : 1;
		DWORD	RSA_4096 : 1;

		DWORD	Reserved : 16;
	}supportedAlgorithms;
	BYTE		otherCapabilities;
} ModuleInfo;

#ifdef __linux__
#define SC_HANDLE					unsigned int
#endif

typedef union _SAC
{
	BYTE compact[8];
	struct _SAC_DETAILES
	{
		BYTE AM;		//Security Attributes Compact:Access Mode
		BYTE SC[7];		//Security Attributes Compact:Security Condition
	} details;
} Sac;					//Security Attributes Compact

typedef struct _SCInfo
{
	BYTE *bInfo;
} SCInfo;

typedef enum _SelectMode
{
	SELECT_MODE_FID = 0,
	SELECT_MODE_NAME = 4,
	SELECT_MODE_PATH = 8
} SelectMode;

typedef enum _SelectPath
{
	FROM_MF = 0,
	FROM_CURRENT_DF = 1
} SelectPath;

typedef enum _SelectFID
{
	GENERIC = 0,
	CHILD_DF = 1,
	EF_IN_CURRENT_DF = 2,
	PARENT_DF = 3
} SelectFID;

typedef enum _FileInfo
{
	FCI = 0,
	FCP = 0x04,
	FMD = 0x08,
	NO_INFO = 0x0C
} FileInfo;

typedef enum _SMMode
{
	SM_IN_RESPONSE = 1,
	SM_IN_COMMAND = 2
} SMMode;

typedef enum _RecordReferenceMode
{
	BY_INDEX = 4,
	BY_ID = 0
} RecordReferenceMode;

typedef enum _RefrencingQualifier
{
	FIRST = 0,
	LAST = 1,
	NEXT = 2,
	PREVIOUS = 3,
	EXACT = 0,
	TO_END = 1,
	FROM_END = 2
} RefrencingQualifier;


typedef enum _ManageChanelOperation
{
	OPEN = 0x00,
	CLOSE = 0x80
}ManageChanelOperation;

typedef enum _SMState
{
	NO_SM = 0x00,
	CMD_SM = 0x10,
	RESP_SM = 0x20,
	CMD_RESP_SM = 0x30
}SMState;

#ifdef __cplusplus
extern "C"
{
#endif

USHORT InitializeLibrary(void *RNG);
void FinalizeLibrary(void *RNG);

#ifdef __cplusplus
};
#endif

#endif

