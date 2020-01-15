
#include "Wrapper_PKCS11.h"
int main()
{
    string pkcsDllPath = "";
    string keyPass = "";
    string content = "";
    CWrapper_PKCS11 obj_wrapper_pkcs11;
    cout << obj_wrapper_pkcs11.loadPkcs11Library(pkcsDllPath);
    obj_wrapper_pkcs11.initializePkcs11Library();
    cout << obj_wrapper_pkcs11.OpenRWSession();

    X509* cert;
    cout << obj_wrapper_pkcs11.findCertificateObject(&cert);
    obj_wrapper_pkcs11.pkcs11Login(keyPass);

    unsigned char* str = (unsigned char*)content.c_str();

    unsigned int cms_signed_data_length = 0;
    string output = obj_wrapper_pkcs11.cmsSignedDataCreate(cert, str, 9, &cms_signed_data_length);
    std::ofstream out("output.txt");
    out << output;
    out.close();
    system("output.txt");
    return 0;
}