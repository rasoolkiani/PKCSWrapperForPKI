#if !defined(AFX_IMPPROTOCOL_H__4369DA69_E8AF_4C2C_9521_06CC59Fc589C__INCLUDED_)
#define AFX_KEYABASEPROTOCOL_H__4369DA69_E8AF_4C2C_9521_06CC59Fc589C__INCLUDED_
#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

typedef int (CALLBACK* CallBackProc)( int attachStatus, LPVOID Param );
#include <stdio.h>

class CBaseKeyA  
{

public:
	virtual UINT	OpenDevice( int KeyAIndex ) = 0;
	virtual UINT	CloseDevice() = 0; 


	virtual UINT	Init( const BYTE*	pKp, const BYTE* pKr, const BYTE*	pKw, const BYTE*		pKw2 ) = 0; 
	virtual UINT	SetCallBackProc(  CallBackProc pAttachCallBack, LPVOID Param) = 0;

	virtual UINT	SetKAB( const BYTE 	*pKA, const BYTE 	*pKAB ) = 0;
	virtual UINT	SetKeyAParameters( const BYTE 	*pKA, const BYTE 	*pData ) = 0;

	virtual UINT	ChangeKAB(const BYTE 	*pKAB, const BYTE 	*pNewKAB) = 0;
	virtual UINT	WriteAccessKey( const BYTE 	*pKBB ) = 0;

	virtual UINT 	ReadPayamPardazMemory( int Address, int Len, BYTE *pBuf ) = 0;
	virtual UINT 	WritePayamPardazMemory( int Address, int Len, const BYTE *pKA, const BYTE *pData ) = 0;

	virtual UINT 	ReadFreeMemory( int Address, int iLen, BYTE	*pBuf ) = 0;
	virtual UINT 	WriteFreeMemory( int Address, int iLen, const BYTE	*pBuf ) = 0;

	virtual UINT 	ReadUserMemory( int Address, int iLen, const BYTE 	*pUserKey,  BYTE 	*pBuf ) = 0;
	virtual UINT 	WriteUserMemory( int Address, int iLen, const BYTE 	*pUserKey,  const BYTE 	*pBuf ) = 0;

	virtual UINT 	ReadUserMemory( int Address, int iLen, BYTE 	*pBuf ) = 0;
	virtual UINT 	WriteUserMemory( int Address, int iLen,const BYTE 	*pBuf ) = 0;

	virtual UINT 	ReadDeveloperMemory( int Address, int iLen, BYTE 	*pBuf ) = 0;
	virtual UINT 	WriteDeveloperMemory( int Address, int iLen, const BYTE 	*pBuf ) = 0;

	virtual UINT	SetMasterPin( const BYTE	*pPin, BYTE PinLen ) = 0;
	virtual UINT	SetUserPin( const BYTE	* pPin, BYTE PinLen ) = 0;
	virtual UINT	UserLogin( const BYTE	* pPin, BYTE PinLen ) = 0;
	virtual UINT	MasterLogin( const BYTE	* pPin, BYTE PinLen ) = 0;

	virtual UINT	SetKV( BYTE  iKVIndex, const BYTE*	pKV ) = 0;
	virtual UINT	EncByKV( BYTE  iKvIndex, const BYTE *pData, BYTE *pRes ) = 0;
	virtual UINT	DecByKV( BYTE  iKvIndex, const BYTE *pData, BYTE *pRes ) = 0;

	virtual UINT	SetQuery( BYTE  iQueryIndex, const BYTE *pQueryKey ) = 0;
	virtual UINT	GetQuery( BYTE  iQueryIndex, const BYTE *pQueryData, BYTE *pQueryResult ) = 0;

	virtual UINT	EncByCustomKey( const BYTE *pCusKey, const BYTE *pData, BYTE *pRes ) = 0;
	virtual UINT	DecByCustomKey( const BYTE *pCusKey, const BYTE *pData, BYTE *pRes ) = 0;

	virtual UINT	CheckModuleExistence() = 0;
	virtual UINT	GetModuleCount() = 0;
	virtual UINT	GetSerialNumber( BYTE *pSerialNum ) = 0; 
	virtual UINT	GetMemoryInfo( int *pDevMemLen, int *pSecMemLen, int *pFMemLen ) = 0;
	virtual UINT	GetVersionInfo( BYTE* pVer, BYTE* pDevMemSup, BYTE* pFmemSup, BYTE* pLoginSup, BYTE* pCusKeySup) = 0;
	virtual UINT	GetKeyCount( int *pQueryKeyNum, int *pKVKeyNum ) = 0;

	virtual UINT	SetMaxClient( BYTE  ClientNum ) = 0;
	virtual UINT	GetMaxClient( BYTE  *pClientNum ) = 0;
	virtual void	GetErrorText( DWORD dwLastError, char *pErrText, size_t nErrTextSize = 0 ) = 0;

	virtual UINT	EncBlock( const BYTE*	pKey, const BYTE *pData, BYTE *pRes ) = 0;
	virtual UINT	DecBlock( const BYTE*	pKey, const BYTE	*pData , BYTE *pRes  ) = 0;
	
	virtual UINT	GetLibVersion() = 0;

	virtual UINT	SetModuleName( const char *strModuleName ) =0;
	virtual UINT	GetModuleName( char *strModuleName, size_t nModuleNameSize = 0 ) = 0;

	virtual UINT	AutoLogin( const  BYTE *pAutoLoginKey  ) = 0;
	virtual UINT	SetAutoLogin( const BYTE *pUserPin, int PinLen, const BYTE *pAutoLoginKey  ) =0;
	virtual UINT	ResetAutoLogin() =0;
	virtual UINT    GetAutoLoginStatus() =0;
};

#endif // !defined(AFX_KEYABASEPROTOCOL_H__4369DA69_E8AF_4C2C_9521_06CC59Fc589C__INCLUDED_)
