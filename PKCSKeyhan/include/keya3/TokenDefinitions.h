#ifndef TOKEN_DEFINITIONS_H
#define TOKEN_DEFINITIONS_H

// Token API definitions:
typedef enum _WrapUnwrapType
{
	SYMM_BY_SYMM,
	SYMM_BY_ASYM,
	ASYM_BY_SYMM
} WrapUnwrapType;

typedef enum _AccessType
{
	PUBLIC_FILE,
	PRIVATE_FILE,
	SHARED_FILE,
	FREE_FILE
} AccessType;

typedef enum _UserType
{
	PAYAMPARDAZ,
	DEVELOPER,
	ADMIN,
	USER,
} UserType;

typedef enum _Model
{
	A,
	B,
	C,
	D
} Model;

typedef enum _MemoryType
{
	DEVELOPER_PRIVATE_MEMORY,
	DEVELOPER_PUBLIC_MEMORY,
	DEVELOPER_SHARED_MEMORY,
	ADMIN_PRIVATE_MEMORY,
	ADMIN_PUBLIC_MEMORY,
	ADMIN_SHARED_MEMORY,
	USER_PRIVATE_MEMORY,
	USER_PUBLIC_MEMORY,
	FREE_MEMORY
} MemoryType;

typedef enum _KeyType
{
	DEVELOPER_PRIVATE_KEY,
	DEVELOPER_PUBLIC_KEY,
	DEVELOPER_SHARED_KEY,
	ADMIN_PRIVATE_KEY,
	ADMIN_PUBLIC_KEY,
	ADMIN_SHARED_KEY,
	USER_PRIVATE_KEY,
	USER_PUBLIC_KEY,
	FREE_KEY
}KeyType;

typedef struct _MemoryVolumes
{
	DWORD developerPrivateMemoryVolume;
	DWORD developerPublicMemoryVolume;
	DWORD developerSharedMemoryVolume;
	DWORD adminPrivateMemoryVolume;
	DWORD adminPublicMemoryVolume;
	DWORD adminSharedMemoryVolume;
	DWORD userPrivateMemoryVolume; 
	DWORD userPublicMemoryVolume;
	DWORD userFreeMemoryVolume;
} MemoryVolumes;

typedef struct _SymKeyCount
{
	USHORT developerPrivateSymKey;
	USHORT developerPublicSymKey;
	USHORT developerSharedSymKey;
	USHORT adminPrivateSymKey;
	USHORT adminPublicSymKey;
	USHORT adminSharedSymKey;
	USHORT userPrivateSymKey; 
	USHORT userPublicSymKey;
	USHORT userFreeSymKey;
} SymKeyCount;

typedef enum _ChannelType
{
	SHARED = 0,
	EXCLUSIVE = 1
}ChannelType;

#endif

