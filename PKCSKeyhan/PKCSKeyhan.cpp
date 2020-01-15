// PKCSKeyhan.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "PKCSKeyhan.h"

void PKCSKeyhan::loadCertificateFromToken(X509* cert)
{
    CK_SLOT_ID slotList[4];
    CK_OBJECT_HANDLE hKey;
    CK_ATTRIBUTE dataTemplate[] = { {CKA_VALUE, NULL_PTR, 0} };
    loadLibrary();
    initialize();
    getSlot(slotList);
    login(slotList[0], tokenPIN);
    getCertificateObjectHandle(&hKey);
    getCertificateAttribute(&hKey, dataTemplate);
    cert = d2i_X509(NULL, (const unsigned char**)&dataTemplate[0].pValue, (int)dataTemplate[0].ulValueLen);
}

void PKCSKeyhan::loadLibrary()
{
    PkcsHandle = LoadLibraryA(libPath.c_str());
    if (!PkcsHandle)
    {
        cout << "error : PKCS library load failed!\n";
        return;
    }
    CK_RV(*pGetFunctionList)(CK_FUNCTION_LIST_PTR_PTR) = (CK_RV(*)(CK_FUNCTION_LIST_PTR_PTR))GetProcAddress(PkcsHandle, "C_GetFunctionList");
    pGetFunctionList(&pFunctionList);
    if (!pFunctionList)
    {
        cout << "error : Invalid PKCS Library. Try again!\n";
        return;
    }
    cout << "success : PKCS11 Library is loaded successfully!\n";
}

void PKCSKeyhan::initialize()
{
    if (!pFunctionList)
    {
        cout << "error : PKCS Library is not loaded.\n";
        return;
    }

    CK_ULONG rv = pFunctionList->C_Initialize(NULL);
    if (rv != CKR_OK)
    {
        pFunctionList->C_Finalize(NULL);
        cout << "error : error in initialize PKCS\n";
        return;
    }
    cout << "success : initialized !\n";
}

void PKCSKeyhan::getSlot(CK_SLOT_ID* slotList)
{
    CK_ULONG slotCount = 4;
    CK_TOKEN_INFO tokenInfo;
    CK_SLOT_INFO slotInfo;
    CK_ULONG rv = pFunctionList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv == CKR_BUFFER_TOO_SMALL)
        rv = pFunctionList->C_GetSlotList(CK_TRUE, slotList, &slotCount);

    if (rv != CKR_OK)
    {
        cout << "error : unable to get slot list.\n";
        return;
    }

    if (slotCount == 0)
    {
        cout << "error : slot count is 0.\n";
        return;
    }
    rv = pFunctionList->C_GetSlotInfo(slotList[0], &slotInfo);
    if (rv != CKR_OK)
    {
        cout << "error : unable to get slot info [0].\n";
        return;
    }
    rv = pFunctionList->C_GetTokenInfo(slotList[0], &tokenInfo);
    if (rv != CKR_OK)
    {
        cout << "error : unable to get token info [0].\n";
        return;
    }
    string str = string((const char*)tokenInfo.label, 32);
    printf("success : get token info of %s \n", str.c_str());
}

void PKCSKeyhan::login(CK_SLOT_ID slot, string pin)
{
    CK_ULONG rv = pFunctionList->C_OpenSession(slot, CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
    if (rv != CKR_OK)
    {
        cout << "error : unable to open session slot.\n";
        return;
    }

    rv = pFunctionList->C_Login(hSession, CKU_USER, (CK_CHAR_PTR)pin.data(), pin.length());
    if (rv == CKR_PIN_INCORRECT)
    {
        cout << "error : pin is incorrect slot.\n";
        return;
    }
    if (rv != CKR_OK)
    {
        cout << "error : unable to login slot.\n";
        return;
    }
    cout << "success : Login !\n";
}

void PKCSKeyhan::getCertificateObjectHandle(CK_OBJECT_HANDLE* hObject)
{
    CK_OBJECT_CLASS obj_Pub = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE  obj_Cert = CKC_X_509;
    CK_ATTRIBUTE objTemplate[] = {
        {CKA_CLASS, &obj_Pub, sizeof(obj_Pub)},
        {CKA_CERTIFICATE_TYPE, &obj_Cert, sizeof(obj_Cert)}
    };

    CK_ULONG rv = pFunctionList->C_FindObjectsInit(hSession, objTemplate, sizeof(objTemplate) / sizeof(CK_ATTRIBUTE));
    if (rv != CKR_OK)
    {
        cout << "error : unable to init find object.\n";
        return;
    }

    CK_OBJECT_HANDLE foundObjects[10];
    CK_ULONG numberOfObjects = 10;
    rv = pFunctionList->C_FindObjects(hSession, foundObjects, sizeof(foundObjects), &numberOfObjects);
    if (rv != CKR_OK)
    {
        cout << "error : unable to find object.\n";
        return;
    }
    rv = pFunctionList->C_FindObjectsFinal(hSession);
    if (rv != CKR_OK)
    {
        cout << "error : unable to final find object.\n";
        return;
    }
    if (numberOfObjects == 0)
    {
        cout << "error : there is no object.\n";
        return;
    }
    *hObject = foundObjects[0];
    cout << "success : Find Certificate !\n";
}

void PKCSKeyhan::getCertificateAttribute(CK_OBJECT_HANDLE* hObject, CK_ATTRIBUTE* dataTemplate)
{
    CK_ULONG rv = pFunctionList->C_GetAttributeValue(hSession, *hObject, dataTemplate, (unsigned long)1);
    if (rv != CKR_OK)
    {
        cout << "error : get attribute failed.\n";
        return;
    }
    if (dataTemplate[0].ulValueLen == 0)
    {
        cout << "error : length of data is 0.\n";
        return;
    }
    dataTemplate[0].pValue = new CK_BYTE[dataTemplate[0].ulValueLen];
    rv = pFunctionList->C_GetAttributeValue(hSession, *hObject, dataTemplate, (unsigned long)1);
    if (rv != CKR_OK)
    {
        cout << "error : unable to get attribute.\n";
        return;
    }
    cout << "success : get certificate attribute!\n";
}

PKCS7* PKCSKeyhan::get_pkcs7_object()
{
    PKCS7* p7 = PKCS7_new();
    p7->type = OBJ_nid2obj(NID_pkcs7_signed);
    return p7;
}

PKCS7_SIGNED* PKCSKeyhan::get_pkcs7_signed_object(PKCS7* p7, X509* cert)
{
    PKCS7_SIGNED* p7s = PKCS7_SIGNED_new();
    p7->d.sign = p7s;
    ASN1_INTEGER_set(p7s->version, 3);
    p7s->cert = get_certificate_stack(cert);
    return p7s;
}

STACK_OF(X509)* PKCSKeyhan::get_certificate_stack(X509* cert)
{
    STACK_OF(X509)* cert_stack = sk_X509_new_null();
    sk_X509_push(cert_stack, cert);
    return cert_stack;
}

PKCS7_SIGNER_INFO* PKCSKeyhan::get_pkcs7_signer_info_object(X509* cert)
{
    PKCS7_SIGNER_INFO* p7si = PKCS7_SIGNER_INFO_new();
    ASN1_INTEGER_set(p7si->version, 1);
    X509_NAME_set(&p7si->issuer_and_serial->issuer, X509_get_issuer_name(cert));

    M_ASN1_INTEGER_free(p7si->issuer_and_serial->serial);
    p7si->pkey = X509_get_pubkey(cert);
    p7si->issuer_and_serial->serial = M_ASN1_INTEGER_dup(X509_get_serialNumber(cert));
    p7si->digest_alg->algorithm = OBJ_nid2obj(NID_sha1);
    ASN1_TYPE_free(p7si->digest_alg->parameter);
    p7si->digest_alg->parameter = ASN1_TYPE_new();
    p7si->digest_alg->parameter->type = V_ASN1_NULL;

    ASN1_TYPE_free(p7si->digest_enc_alg->parameter);
    p7si->digest_enc_alg->algorithm = OBJ_nid2obj(NID_sha1WithRSAEncryption);
    p7si->digest_enc_alg->parameter = ASN1_TYPE_new();
    p7si->digest_enc_alg->parameter->type = V_ASN1_NULL;

    return p7si;
}

void PKCSKeyhan::get_hash_data(unsigned char* data, unsigned int data_len, unsigned char* md_data, unsigned int* md_len)
{
    EVP_MD_CTX ctx;
    EVP_MD_CTX_init(&ctx);
    EVP_DigestInit_ex(&ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(&ctx, data, data_len);
    EVP_DigestFinal_ex(&ctx, md_data, md_len);
}

void PKCSKeyhan::set_signer_attribute(PKCS7_SIGNER_INFO* p7si, unsigned char* md_data, unsigned int md_len)
{
    ASN1_OCTET_STRING* digest_attr = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(digest_attr, md_data, (int)md_len);
    PKCS7_add_signed_attribute(p7si, NID_pkcs9_messageDigest, V_ASN1_OCTET_STRING, digest_attr);

    ASN1_OBJECT* oid = OBJ_txt2obj("1.2.840.113549.1.9.15", 1);
    PKCS7_add_signed_attribute(p7si, NID_pkcs9_contentType, V_ASN1_OBJECT, oid);

    ASN1_UTCTIME* sign_time = X509_gmtime_adj(NULL, 0);
    PKCS7_add_signed_attribute(p7si, NID_pkcs9_signingTime, V_ASN1_UTCTIME, sign_time);
}

ASN1_STRING* PKCSKeyhan::get_signer_attribute(PKCS7_SIGNER_INFO* p7si, unsigned char* md_data, unsigned int md_len)
{
    set_signer_attribute(p7si, md_data, md_len);
    ASN1_STRING* seq = ASN1_STRING_new();
    seq->length = ASN1_item_i2d((ASN1_VALUE*)p7si->auth_attr, &seq->data, ASN1_ITEM_rptr(PKCS7_ATTR_SIGN));
    return seq;
}

unsigned int PKCSKeyhan::get_algorithm_len(X509_ALGOR* alg)
{
    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_sha1), V_ASN1_NULL, NULL);
    alg->algorithm = OBJ_nid2obj(NID_sha1);
    alg->parameter = NULL;
    return i2d_X509_ALGOR(alg, NULL);
}

unsigned int PKCSKeyhan::get_digest_len(ASN1_OCTET_STRING* digest, unsigned char* md_data2, unsigned int md_len2)
{
    ASN1_OCTET_STRING_set(digest, md_data2, (int)md_len2);
    return i2d_ASN1_OCTET_STRING(digest, NULL);
}

unsigned char* PKCSKeyhan::get_digest_info_buffer(X509_ALGOR* alg, unsigned int alg_len, ASN1_OCTET_STRING* digest, unsigned int digest_len, unsigned int* digestInfo_len)
{
    *digestInfo_len = ASN1_object_size(1, (int)(alg_len + digest_len), V_ASN1_SEQUENCE);
    unsigned char* digestInfo_buf, * y;
    y = digestInfo_buf = new unsigned char[*digestInfo_len];
    ASN1_put_object(&y, 1, (int)(alg_len + digest_len), V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
    i2d_X509_ALGOR(alg, &y);
    i2d_ASN1_OCTET_STRING(digest, &y);
    return digestInfo_buf;
}

string PKCSKeyhan::get_private_key_handle(CK_OBJECT_HANDLE* hObject)
{
    CK_OBJECT_CLASS classType = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE objTemplate[] = { { CKA_CLASS, &classType, sizeof(classType)} };

    return findPkcs11Object(hObject, objTemplate, sizeof(objTemplate) / sizeof(CK_ATTRIBUTE));
}

string PKCSKeyhan::findPkcs11Object(CK_OBJECT_HANDLE* hObject, CK_ATTRIBUTE* objTemplate, int attr_count)
{
    CK_ULONG rv = pFunctionList->C_FindObjectsInit(hSession, objTemplate, attr_count);
    if (rv != CKR_OK)
        return "";

    CK_OBJECT_HANDLE			foundObjects[10];
    CK_ULONG					numberOfObjects = 10;
    rv = pFunctionList->C_FindObjects(hSession, foundObjects, sizeof(foundObjects), &numberOfObjects);
    if (rv != CKR_OK)
        return "";

    rv = pFunctionList->C_FindObjectsFinal(hSession);
    if (rv != CKR_OK)
        return "";

    if (numberOfObjects == 0)
        return "";

    *hObject = foundObjects[0];
    return "";
}

string PKCSKeyhan::sign_by_pkcs11(unsigned char* data, int dataLen, unsigned char** signedData, CK_ULONG* signedDataLength)
{
    CK_OBJECT_HANDLE hKey;
    string str_result = get_private_key_handle(&hKey);
    if (str_result != "")
        return "error";

    CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
    CK_RV rv = pFunctionList->C_SignInit(hSession, &mechanism, hKey);
    if (rv != CKR_OK)
        return "error";

    rv = pFunctionList->C_Sign(hSession, data, dataLen, NULL, signedDataLength);
    if (rv != CKR_OK)
        return "error";

    *signedData = new unsigned char[*signedDataLength];
    rv = pFunctionList->C_Sign(hSession, data, dataLen, *signedData, signedDataLength);
    if (rv != CKR_OK)
        return "error";

    return "";
}

char* PKCSKeyhan::signData(X509* cert, unsigned char* data, unsigned int dataLen, unsigned int* cmsSignedDataLen)
{
    OpenSSL_add_all_algorithms();
    PKCS7* p7 = get_pkcs7_object();
    PKCS7_SIGNED* p7s = get_pkcs7_signed_object(p7, cert);
    PKCS7_SIGNER_INFO* p7si = get_pkcs7_signer_info_object(cert);

    unsigned int md_len;
    unsigned char md_data[EVP_MAX_MD_SIZE];
    get_hash_data(data, dataLen, md_data, &md_len);

    ASN1_STRING* seq = get_signer_attribute(p7si, md_data, md_len);

    unsigned int md_len2;
    unsigned char md_data2[EVP_MAX_MD_SIZE];
    get_hash_data(seq->data, seq->length, md_data2, &md_len2);

    X509_ALGOR* alg = X509_ALGOR_new();
    unsigned int alg_len = get_algorithm_len(alg);

    ASN1_OCTET_STRING* digest = ASN1_OCTET_STRING_new();
    unsigned int digest_len = get_digest_len(digest, md_data2, md_len2);

    unsigned int digestInfo_len;
    unsigned char* digestInfo_buf = get_digest_info_buffer(alg, alg_len, digest, digest_len, &digestInfo_len);

    CK_ULONG sign_data_len;
    unsigned char* sign_data;
    string str_result = sign_by_pkcs11(digestInfo_buf, digestInfo_len, &sign_data, &sign_data_len);
    if (str_result != "")
        return str_result;

    add_to_json_string(json_output, "sign_by_pkcs11", "Data is signed successfully by PKCS11!");

    set_signer_to_pkcs7_object(p7, p7si, sign_data, sign_data_len);
    create_contentinfo(p7s, data, data_len);
    unsigned char* cms_signed_data = get_cms_signed_data(p7, cms_signed_data_len);


    add_to_json_string(json_output, "command", "success");
    add_to_json_string(json_output, "message", get_substr_final_cms(get_final_cms(cms_signed_data, *cms_signed_data_len)));

    stringstream buf;
    buf << *json_output;
    return buf.str();
    //return create_json_string("success", get_substr_final_cms(get_final_cms(get_cms_signed_data(p7, cms_signed_data_len), *cms_signed_data_len)), tab);
}

