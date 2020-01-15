// KeyA.h: interface for the CKeyA class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_KEYA2H__E96BF17B_9CDF_478F_8FF7_35B91715A5B5__INCLUDED_)
#define AFX_KEYA2H__E96BF17B_9CDF_478F_8FF7_35B91715A5B5__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif 
#include "windows.h"
#include "BaseKeyA.h"

//KeyA Device Type
#define _HID_CLASS				1
#define _CUSTOME_CLASS			0

//KeyA Version
#define _KEYA2_FUNCTIONALITY	1
#define _KEYA1_FUNCTIONALITY	0

//KeyA Model
#define _L_MODEL				0
#define _M_MODEL				1
#define _N_MODEL				2
#define _W_MODEL				3
#define _WMIN_MODEL				4
#define _NW_MODEL				5

//KeyA Attach Status 
#define _KEYA_LOCAL_ATTACHED	1
#define _KEYA_LOCAL_DETACHED	0

//#define _KEYA_NET_LIB

//Callback Function Definition
typedef int (CALLBACK* CallBackProc)( int attachStatus, LPVOID Param );

class CKeyA :	public CBaseKeyA 
{
	CKeyA(CKeyA &);
public: 
	CKeyA( DWORD dwModuleType = _HID_CLASS );
	virtual	~CKeyA();
	UINT	OpenDevice( int KeyAIndex );
	UINT	CloseDevice(); 

	UINT	SetModuleType( DWORD dwModuleType );
	UINT 	SetKeyAFunctionality( DWORD dwKeyAFun );

	UINT	Init( const BYTE*	pKp, const BYTE* pKr, const BYTE*	pKw, const BYTE*		pKw2 ); 
	UINT	SetCallBackProc(  CallBackProc pAttachCallBack, LPVOID Param);

	UINT	SetKAB( const BYTE 	*pKA, const BYTE 	*pKAB );
	UINT	SetKeyAParameters( const BYTE 	*pKA, const BYTE 	*pData );

	UINT	ChangeKAB(const BYTE 	*pKAB, const BYTE 	*pNewKAB);
	UINT	WriteAccessKey( const BYTE 	*pKBB );

	UINT 	ReadPayamPardazMemory( int Address, int Len, BYTE *pBuf );
	UINT 	WritePayamPardazMemory( int Address, int Len, const BYTE *pKA, const BYTE *pData );

	UINT 	ReadFreeMemory( int Address, int iLen, BYTE	*pBuf );
	UINT 	WriteFreeMemory( int Address, int iLen, const BYTE	*pBuf );

	UINT 	ReadUserMemory( int Address, int iLen, const BYTE 	*pUserKey,  BYTE 	*pBuf );
	UINT 	WriteUserMemory( int Address, int iLen, const BYTE 	*pUserKey,  const BYTE 	*pBuf );

	UINT 	ReadUserMemory( int Address, int iLen, BYTE 	*pBuf );
	UINT 	WriteUserMemory( int Address, int iLen,const BYTE 	*pBuf );

	UINT 	ReadDeveloperMemory( int Address, int iLen, BYTE 	*pBuf );
	UINT 	WriteDeveloperMemory( int Address, int iLen, const BYTE 	*pBuf );

	UINT	SetMasterPin( const BYTE	*pPin, BYTE PinLen );
	UINT	SetUserPin( const BYTE	* pPin, BYTE PinLen );
	UINT	UserLogin( const BYTE	* pPin, BYTE PinLen );
	UINT	MasterLogin( const BYTE	* pPin, BYTE PinLen );

	UINT	SetKV( BYTE  iKVIndex, const BYTE*	pKV );
	UINT	EncByKV( BYTE  iKvIndex, const BYTE *pData, BYTE *pRes );
	UINT	DecByKV( BYTE  iKvIndex, const BYTE *pData, BYTE *pRes );

	UINT	SetQuery( BYTE  iQueryIndex, const BYTE *pQueryKey );
	UINT	GetQuery( BYTE  iQueryIndex, const BYTE *pQueryData, BYTE *pQueryResult );

	UINT	EncByCustomKey( const BYTE *pCusKey, const BYTE *pData, BYTE *pRes );
	UINT	DecByCustomKey( const BYTE *pCusKey, const BYTE *pData, BYTE *pRes );

	UINT	CheckModuleExistence();
	UINT	GetModuleCount();
	UINT	GetSerialNumber( BYTE *pSerialNum ); 
	UINT	GetMemoryInfo( int *pDevMemLen, int *pSecMemLen, int *pFMemLen );
	UINT	GetVersionInfo( BYTE* pVer, BYTE* pDevMemSup, BYTE* pFmemSup, BYTE* pLoginSup, BYTE* pCusKeySup);
	UINT	GetKeyCount( int *pQueryKeyNum, int *pKVKeyNum );

	UINT	SetMaxClient( BYTE  ClientNum );
	UINT	GetMaxClient( BYTE  *pClientNum );
	void	GetErrorText( DWORD dwLastError, char *pErrText, size_t nErrTextSize = 0 );

	UINT	EncBlock( const BYTE*	pKey, const BYTE *pData, BYTE *pRes );
	UINT	DecBlock( const BYTE*	pKey, const BYTE	*pData , BYTE *pRes  );
	
	UINT	GetLibVersion();

	UINT	SetModuleName( const char *strModuleName );
	UINT	GetModuleName( char *strModuleName, size_t nModuleNameSize = 0 );

	UINT	AutoLogin( const  BYTE *pAutoLoginKey  );
	UINT	SetAutoLogin( const BYTE *pUserPin, int PinLen, const BYTE *pAutoLoginKey  );
	UINT	ResetAutoLogin();
	UINT    GetAutoLoginStatus();

#ifdef _KEYA_NET_LIB
	UINT	GetCurrentAccessKey( BYTE*	pKp, BYTE* pKr, BYTE*	pKw, BYTE*		pKw2 );
	UINT	NetInit( const BYTE*	pKp, const BYTE* pKr, const BYTE*	pKw , const BYTE*	pKw2 );
#endif
private:
	LPVOID m_DeviceHandel;
};

#endif // !defined(AFX_KEYA2H__E96BF17B_9CDF_478F_8FF7_35B91715A5B5__INCLUDED_)

