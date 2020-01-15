#pragma once

#include <iostream>
#include <fstream>
#include <sstream>
#include "AtlBase.h"
#include "prsht.h"
#include "Wincrypt.h"
#include "Cryptuiapi.h"
#include <io.h>
#include <fcntl.h>
#include <vector> 

#include <utility>
#include <iomanip>
#include <string>
#include <wtypes.h>
#include <memory>
#include <atlbase.h>
#include <atlconv.h>

#include "pkcs11.h"
#include "openssl/asn1.h"
#include "openssl/pem.h"
#include "openssl/cms.h"
#include "openssl/err.h"
#include "openssl/x509.h"

using std::string;
using std::stringstream;
using std::wstring;
using namespace std;
class CWrapper_PKCS11
{
    HMODULE PKCS_Handle;
    CK_SESSION_HANDLE hSession;
    CK_FUNCTION_LIST_PTR pFunctionList;
    CK_SLOT_ID slotList[4];
    CK_ULONG slotCount = 4;

    STACK_OF(X509)* getCertificateStack(X509* cert);
    void createContentinfo(PKCS7_SIGNED* p7s, unsigned char* data, size_t data_len);
    PKCS7* getPkcs7Object();
    PKCS7_SIGNED* getPkcs7SignedObject(PKCS7* p7, X509* cert);
    PKCS7_SIGNER_INFO* getPkcs7SignerInfoObject(X509* cert);
    ASN1_STRING* getSignerAttribute(PKCS7_SIGNER_INFO* p7si, unsigned char* md_data, unsigned int md_len);
    void getHashData(unsigned char* data, unsigned int data_len, unsigned char* md_data, unsigned int* md_len);
    void setSignerAttribute(PKCS7_SIGNER_INFO* p7si, unsigned char* md_data, unsigned int md_len);
    void setSignerToPkcs7Object(PKCS7* p7, PKCS7_SIGNER_INFO* p7si, unsigned char* signed_data, unsigned int signed_data_len);
    unsigned int getAlgorithmLen(X509_ALGOR* alg);
    unsigned int getDigestLen(ASN1_OCTET_STRING* digest, unsigned char* md_data2, unsigned int md_len2);
    unsigned char* getDigestInfoBuffer(X509_ALGOR* alg, unsigned int alg_len, ASN1_OCTET_STRING* digest, unsigned int digest_len, unsigned int* digestInfo_len);
    unsigned char* getCmsSignedData(PKCS7* p7, unsigned int* cms_signed_data_len);
    char* getFinalCms(unsigned char* cms_signed_data, unsigned int cms_signed_data_len);
    string getSubstrFinalCms(string str_res);

public:
    CK_ULONG loadPkcs11Library(string pkcs_lib_path_name);
    CK_ULONG unLoadPkcs11Library();
    CK_ULONG initializePkcs11Library();
    CK_ULONG getSlot(CK_SLOT_INFO* slotInfo, CK_TOKEN_INFO* tokenInfo, CK_INFO* info);
    CK_ULONG openRwSession();
    CK_ULONG pkcs11Login(string pin);
    CK_ULONG OpenRWSession();
    string getErrorCode(CK_ULONG rv);
    string signByPkcs11(unsigned char* data, int data_len, unsigned char** signedData, CK_ULONG* signedDataLength);
    CK_ULONG getPrivateKeyHandle(CK_OBJECT_HANDLE* hObject);
    CK_ULONG getCertificateObjectHandle(CK_OBJECT_HANDLE* hObject);
    CK_ULONG getCertificateAttribute(CK_OBJECT_HANDLE* hObject, CK_ATTRIBUTE* dataTemplate);
    CK_ULONG findPkcs11Object(CK_OBJECT_HANDLE* hObject, CK_ATTRIBUTE* objTemplate, int attr_count);
    CK_ULONG findCertificateObject(X509** cert);
    string cmsSignedDataCreate(X509* cert, unsigned char* data, unsigned int data_len, unsigned int* cms_signed_data_len);

};

