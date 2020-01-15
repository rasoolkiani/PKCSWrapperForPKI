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
public:
    void loadCertificateFromToken(X509* cert);
};
