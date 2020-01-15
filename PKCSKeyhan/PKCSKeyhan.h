#pragma once
#include "pkcs11.h"
#include <iostream>
#include <utility>
#include <iomanip>
#include <string>
#include <wtypes.h>
#include <memory>
#include <atlbase.h>
#include <atlconv.h>
#include "openssl/x509.h"
using namespace std;
class PKCSKeyhan {
private:
    HMODULE PkcsHandle;
    string libPath = "k3pkcs11.dll";
    string tokenPIN = "keya";
    CK_FUNCTION_LIST_PTR pFunctionList;
    CK_SESSION_HANDLE hSession;
    void loadLibrary();
    void initialize();
    void getSlot(CK_SLOT_ID *slotList);
    void login(CK_SLOT_ID slot, string pin);
    void getCertificateObjectHandle(CK_OBJECT_HANDLE* hObject);
    void getCertificateAttribute(CK_OBJECT_HANDLE* hObject, CK_ATTRIBUTE* dataTemplate);
    PKCS7* get_pkcs7_object();
    PKCS7_SIGNED* get_pkcs7_signed_object(PKCS7* p7, X509* cert);
    STACK_OF(X509)* get_certificate_stack(X509* cert);
    PKCS7_SIGNER_INFO* get_pkcs7_signer_info_object(X509* cert);
    void get_hash_data(unsigned char* data, unsigned int data_len, unsigned char* md_data, unsigned int* md_len);
    void set_signer_attribute(PKCS7_SIGNER_INFO* p7si, unsigned char* md_data, unsigned int md_len);
    ASN1_STRING* get_signer_attribute(PKCS7_SIGNER_INFO* p7si, unsigned char* md_data, unsigned int md_len);
    unsigned int get_algorithm_len(X509_ALGOR* alg);
    unsigned int get_digest_len(ASN1_OCTET_STRING* digest, unsigned char* md_data2, unsigned int md_len2);
    unsigned char* get_digest_info_buffer(X509_ALGOR* alg, unsigned int alg_len, ASN1_OCTET_STRING* digest, unsigned int digest_len, unsigned int* digestInfo_len);
    string get_private_key_handle(CK_OBJECT_HANDLE* hObject);
    string findPkcs11Object(CK_OBJECT_HANDLE* hObject, CK_ATTRIBUTE* objTemplate, int attr_count);
    string sign_by_pkcs11(unsigned char* data, int dataLen, unsigned char** signedData, CK_ULONG* signedDataLength);
    char* signData(X509* cert, unsigned char* data, unsigned int dataLen, unsigned int* cmsSignedDataLen);
public:
    void loadCertificateFromToken(X509* cert);
};
