
#include "Wrapper_PKCS11.h"

CK_ULONG CWrapper_PKCS11::loadPkcs11Library(string pkcs_lib_path_name)
{
    PKCS_Handle = LoadLibraryA(pkcs_lib_path_name.c_str());
    if (!PKCS_Handle)
        return CKR_GENERAL_ERROR;
    CK_RV(*pGetFunctionList)(CK_FUNCTION_LIST_PTR_PTR) = (CK_RV(*)(CK_FUNCTION_LIST_PTR_PTR))GetProcAddress(PKCS_Handle, "C_GetFunctionList");
    pGetFunctionList(&pFunctionList);
    if (!pFunctionList)
        return CKR_FUNCTION_FAILED;
    return CKR_OK;
}

CK_ULONG CWrapper_PKCS11::initializePkcs11Library()
{
    CK_ULONG rv = pFunctionList->C_Initialize(NULL);
    if (rv != CKR_OK)
    {
        pFunctionList->C_Finalize(NULL);
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    return  rv;
}

CK_ULONG CWrapper_PKCS11::getSlot(CK_SLOT_INFO* slotInfo, CK_TOKEN_INFO* tokenInfo, CK_INFO* info)
{
    CK_ULONG rv = pFunctionList->C_GetSlotList(CK_TRUE, slotList, &slotCount);
    if (rv == CKR_BUFFER_TOO_SMALL)
        rv = pFunctionList->C_GetSlotList(CK_TRUE, slotList, &slotCount);

    if (rv != CKR_OK)
        return CKR_TOKEN_NOT_PRESENT;

    if (slotCount == 0)
        return CKR_TOKEN_NOT_PRESENT;

    rv = pFunctionList->C_GetSlotInfo(slotList[0], slotInfo);
    if (rv != CKR_OK)
        return CKR_SLOT_ID_INVALID;

    rv = pFunctionList->C_GetTokenInfo(slotList[0], tokenInfo);
    if (rv != CKR_OK)
        return CKR_TOKEN_NOT_RECOGNIZED;

    return CKR_OK;
}

CK_ULONG CWrapper_PKCS11::openRwSession()
{
    return pFunctionList->C_OpenSession(slotList[0], CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL, NULL, &hSession);
}

CK_ULONG CWrapper_PKCS11::pkcs11Login(string pin)
{
    return pFunctionList->C_Login(hSession, CKU_USER, (CK_CHAR_PTR)pin.data(), pin.length());
}

CK_ULONG CWrapper_PKCS11::unLoadPkcs11Library()
{
    PKCS_Handle = NULL;
    pFunctionList->C_Finalize(NULL);
    pFunctionList->C_CloseSession(hSession);
    hSession = NULL;
    return 0;
}

CK_ULONG CWrapper_PKCS11::OpenRWSession()
{
    if (PKCS_Handle == NULL)
        return CKR_GENERAL_ERROR;

    CK_SLOT_INFO slotInfo;
    CK_TOKEN_INFO tokenInfo;
    CK_INFO info;
    CK_ULONG rv = getSlot(&slotInfo, &tokenInfo, &info);
    if (CKR_OK != rv)
        return 1;

    rv = openRwSession();
    if (rv != CKR_OK)
        return 2;

    return 0;
}

string CWrapper_PKCS11::getErrorCode(CK_ULONG rv)
{
    switch (rv)
    {
    case 0x00000000:	return "OK";								break;
    case 0x00000001:	return "CANCEL";							break;
    case 0x00000002:	return "HOST_MEMORY";						break;
    case 0x00000003:	return "SLOT_ID_INVALID";					break;
    case 0x00000005:	return "GENERAL_ERROR";						break;
    case 0x00000006:	return "FUNCTION_FAILED";					break;
    case 0x00000007:	return "ARGUMENTS_BAD";						break;
    case 0x00000008:	return "NO_EVENT";							break;
    case 0x00000009:	return "NEED_TO_CREATE_THREADS";			break;
    case 0x0000000A:	return "CANT_LOCK";							break;
    case 0x00000010:	return "ATTRIBUTE_READ_ONLY";				break;
    case 0x00000011:	return "ATTRIBUTE_SENSITIVE";				break;
    case 0x00000012:	return "ATTRIBUTE_TYPE_INVALID";			break;
    case 0x00000013:	return "ATTRIBUTE_VALUE_INVALID";			break;
    case 0x00000020:	return "DATA_INVALID";						break;
    case 0x00000021:	return "DATA_LEN_RANGE";					break;
    case 0x00000030:	return "DEVICE_ERROR";						break;
    case 0x00000031:	return "DEVICE_MEMORY";						break;
    case 0x00000032:	return "DEVICE_REMOVED";					break;
    case 0x00000040:	return "ENCRYPTED_DATA_INVALID";			break;
    case 0x00000041:	return "ENCRYPTED_DATA_LEN_RANGE";			break;
    case 0x00000050:	return "FUNCTION_CANCELED";					break;
    case 0x00000051:	return "FUNCTION_NOT_PARALLEL";				break;
    case 0x00000054:	return "FUNCTION_NOT_SUPPORTED";			break;
    case 0x00000060:	return "KEY_HANDLE_INVALID";				break;
    case 0x00000062:	return "KEY_SIZE_RANGE";					break;
    case 0x00000063:	return "KEY_TYPE_INCONSISTENT";				break;
    case 0x00000064:	return "KEY_NOT_NEEDED";					break;
    case 0x00000065:	return "KEY_CHANGED";						break;
    case 0x00000066:	return "KEY_NEEDED";						break;
    case 0x00000067:	return "KEY_INDIGESTIBLE";					break;
    case 0x00000068:	return "KEY_FUNCTION_NOT_PERMITTED";		break;
    case 0x00000069:	return "KEY_NOT_WRAPPABLE";					break;
    case 0x0000006A:	return "KEY_UNEXTRACTABLE";					break;
    case 0x00000070:	return "MECHANISM_INVALID";					break;
    case 0x00000071:	return "MECHANISM_PARAM_INVALID";			break;
    case 0x00000082:	return "OBJECT_HANDLE_INVALID";				break;
    case 0x00000090:	return "OPERATION_ACTIVE";					break;
    case 0x00000091:	return "OPERATION_NOT_INITIALIZED";			break;
    case 0x000000A0:	return "PIN_INCORRECT";						break;
    case 0x000000A1:	return "PIN_INVALID";						break;
    case 0x000000A2:	return "PIN_LEN_RANGE";						break;
    case 0x000000A3:	return "PIN_EXPIRED";						break;
    case 0x000000A4:	return "PIN_LOCKED";						break;
    case 0x000000B0:	return "SESSION_CLOSED";					break;
    case 0x000000B1:	return "SESSION_COUNT";						break;
    case 0x000000B3:	return "SESSION_HANDLE_INVALID";			break;
    case 0x000000B4:	return "SESSION_PARALLEL_NOT_SUPPORTED";	break;
    case 0x000000B5:	return "SESSION_READ_ONLY";					break;
    case 0x000000B6:	return "SESSION_EXISTS";					break;
    case 0x000000B7:	return "SESSION_READ_ONLY_EXISTS";			break;
    case 0x000000B8:	return "SESSION_READ_WRITE_SO_EXISTS";		break;
    case 0x000000C0:	return "SIGNATURE_INVALID";					break;
    case 0x000000C1:	return "SIGNATURE_LEN_RANGE";				break;
    case 0x000000D0:	return "TEMPLATE_INCOMPLETE";				break;
    case 0x000000D1:	return "TEMPLATE_INCONSISTENT";				break;
    case 0x000000E0:	return "TOKEN_NOT_PRESENT";					break;
    case 0x000000E1:	return "TOKEN_NOT_RECOGNIZED";				break;
    case 0x000000E2:	return "TOKEN_WRITE_PROTECTED";				break;
    case 0x000000F0:	return "UNWRAPPING_KEY_HANDLE_INVALID";		break;
    case 0x000000F1:	return "UNWRAPPING_KEY_SIZE_RANGE";			break;
    case 0x000000F2:	return "UNWRAPPING_KEY_TYPE_INCONSISTENT";	break;
    case 0x00000100:	return "USER_ALREADY_LOGGED_IN";			break;
    case 0x00000101:	return "USER_NOT_LOGGED_IN";				break;
    case 0x00000102:	return "USER_PIN_NOT_INITIALIZED";			break;
    case 0x00000103:	return "USER_TYPE_INVALID";					break;
    case 0x00000104:	return "USER_ANOTHER_ALREADY_LOGGED_IN";	break;
    case 0x00000105:	return "USER_TOO_MANY_TYPES";				break;
    case 0x00000110:	return "WRAPPED_KEY_INVALID";				break;
    case 0x00000112:	return "WRAPPED_KEY_LEN_RANGE";				break;
    case 0x00000113:	return "WRAPPING_KEY_HANDLE_INVALID";		break;
    case 0x00000114:	return "WRAPPING_KEY_SIZE_RANGE";			break;
    case 0x00000115:	return "WRAPPING_KEY_TYPE_INCONSISTENT";	break;
    case 0x00000120:	return "RANDOM_SEED_NOT_SUPPORTED";			break;
    case 0x00000121:	return "RANDOM_NO_RNG";						break;
    case 0x00000130:	return "DOMAIN_PARAMS_INVALID";				break;
    case 0x00000150:	return "BUFFER_TOO_SMALL";					break;
    case 0x00000160:	return "SAVED_STATE_INVALID";				break;
    case 0x00000170:	return "INFORMATION_SENSITIVE";				break;
    case 0x00000180:	return "STATE_UNSAVEABLE";					break;
    case 0x00000190:	return "CRYPTOKI_NOT_INITIALIZED";			break;
    case 0x00000191:	return "CRYPTOKI_ALREADY_INITIALIZED";		break;
    case 0x000001A0:	return "MUTEX_BAD";							break;
    case 0x000001A1:	return "MUTEX_NOT_LOCKED";					break;
    case 0x00000200:	return "FUNCTION_REJECTED";					break;
    case 0x80000000:	return "VENDOR_DEFINED";					break;
    }
    return "Unknown Error";
}

CK_ULONG CWrapper_PKCS11::findCertificateObject(X509** cert)
{
    CK_OBJECT_HANDLE hObject = CK_INVALID_HANDLE;
    CK_ULONG rv = getCertificateObjectHandle(&hObject);
    if (rv != CKR_OK)
        return rv;

    CK_ATTRIBUTE dataTemplate[] = { {CKA_VALUE, NULL_PTR, 0} };
    rv = getCertificateAttribute(&hObject, dataTemplate);
    if (rv != CKR_OK)
        return rv;

    *cert = d2i_X509(NULL, (const unsigned char**)&dataTemplate[0].pValue, (int)dataTemplate[0].ulValueLen);
    return CKR_OK;
}

STACK_OF(X509)* CWrapper_PKCS11::getCertificateStack(X509* cert)
{
    STACK_OF(X509)* cert_stack = sk_X509_new_null();
    sk_X509_push(cert_stack, cert);
    return cert_stack;
}

PKCS7* CWrapper_PKCS11::getPkcs7Object()
{
    PKCS7* p7 = PKCS7_new();
    p7->type = OBJ_nid2obj(NID_pkcs7_signed);
    return p7;
}

PKCS7_SIGNED* CWrapper_PKCS11::getPkcs7SignedObject(PKCS7* p7, X509* cert)
{
    PKCS7_SIGNED* p7s = PKCS7_SIGNED_new();
    p7->d.sign = p7s;
    ASN1_INTEGER_set(p7s->version, 3);
    p7s->cert = getCertificateStack(cert);
    return p7s;
}

ASN1_STRING* CWrapper_PKCS11::getSignerAttribute(PKCS7_SIGNER_INFO* p7si, unsigned char* md_data, unsigned int md_len)
{
    setSignerAttribute(p7si, md_data, md_len);
    ASN1_STRING* seq = ASN1_STRING_new();
    seq->length = ASN1_item_i2d((ASN1_VALUE*)p7si->auth_attr, &seq->data, ASN1_ITEM_rptr(PKCS7_ATTR_SIGN));
    return seq;
}

PKCS7_SIGNER_INFO* CWrapper_PKCS11::getPkcs7SignerInfoObject(X509* cert)
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

void CWrapper_PKCS11::getHashData(unsigned char* data, unsigned int data_len, unsigned char* md_data, unsigned int* md_len)
{
    EVP_MD_CTX ctx;
    EVP_MD_CTX_init(&ctx);
    EVP_DigestInit_ex(&ctx, EVP_sha1(), NULL);
    EVP_DigestUpdate(&ctx, data, data_len);
    EVP_DigestFinal_ex(&ctx, md_data, md_len);
}

void CWrapper_PKCS11::setSignerAttribute(PKCS7_SIGNER_INFO* p7si, unsigned char* md_data, unsigned int md_len)
{
    ASN1_OCTET_STRING* digest_attr = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(digest_attr, md_data, (int)md_len);
    PKCS7_add_signed_attribute(p7si, NID_pkcs9_messageDigest, V_ASN1_OCTET_STRING, digest_attr);

    ASN1_OBJECT* oid = OBJ_txt2obj("1.2.840.113549.1.9.15", 1);
    PKCS7_add_signed_attribute(p7si, NID_pkcs9_contentType, V_ASN1_OBJECT, oid);

    ASN1_UTCTIME* sign_time = X509_gmtime_adj(NULL, 0);
    PKCS7_add_signed_attribute(p7si, NID_pkcs9_signingTime, V_ASN1_UTCTIME, sign_time);
}

void CWrapper_PKCS11::setSignerToPkcs7Object(PKCS7* p7, PKCS7_SIGNER_INFO* p7si, unsigned char* sign_data, unsigned int sign_data_len)
{
    ASN1_STRING_set(p7si->enc_digest, (unsigned char*)sign_data, (int)sign_data_len);
    PKCS7_add_signer(p7, p7si);
}

unsigned int CWrapper_PKCS11::getAlgorithmLen(X509_ALGOR* alg)
{
    X509_ALGOR_set0(alg, OBJ_nid2obj(NID_sha1), V_ASN1_NULL, NULL);
    alg->algorithm = OBJ_nid2obj(NID_sha1);
    alg->parameter = NULL;
    return i2d_X509_ALGOR(alg, NULL);
}

unsigned int CWrapper_PKCS11::getDigestLen(ASN1_OCTET_STRING* digest, unsigned char* md_data2, unsigned int md_len2)
{
    ASN1_OCTET_STRING_set(digest, md_data2, (int)md_len2);
    return i2d_ASN1_OCTET_STRING(digest, NULL);
}

unsigned char* CWrapper_PKCS11::getDigestInfoBuffer(X509_ALGOR* alg, unsigned int alg_len, ASN1_OCTET_STRING* digest, unsigned int digest_len, unsigned int* digestInfo_len)
{
    *digestInfo_len = ASN1_object_size(1, (int)(alg_len + digest_len), V_ASN1_SEQUENCE);
    unsigned char* digestInfo_buf, * y;
    y = digestInfo_buf = new unsigned char[*digestInfo_len];
    ASN1_put_object(&y, 1, (int)(alg_len + digest_len), V_ASN1_SEQUENCE, V_ASN1_UNIVERSAL);
    i2d_X509_ALGOR(alg, &y);
    i2d_ASN1_OCTET_STRING(digest, &y);
    return digestInfo_buf;
}

unsigned char* CWrapper_PKCS11::getCmsSignedData(PKCS7* p7, unsigned int* cms_signed_data_len)
{
    *cms_signed_data_len = i2d_PKCS7(p7, NULL);
    unsigned char* p, * cms_signed_data;
    p = cms_signed_data = (unsigned char*)OPENSSL_malloc(*cms_signed_data_len);
    i2d_PKCS7(p7, &p);

    return cms_signed_data;
}

char* CWrapper_PKCS11::getFinalCms(unsigned char* cms_signed_data, unsigned int cms_signed_data_len)
{
    BIO* in = BIO_new(BIO_s_mem());
    BIO_write(in, cms_signed_data, cms_signed_data_len);

    CMS_ContentInfo* cms = CMS_data_create(in, CMS_STREAM | CMS_BINARY);
    BIO* out = BIO_new(BIO_s_mem());

    PEM_write_bio_CMS_stream(out, cms, in, CMS_STREAM | CMS_BINARY);

    char* res = new char[out->num_write + 1];
    BIO_read(out, res, out->num_write);

    return res;
}

string CWrapper_PKCS11::getSubstrFinalCms(string str_res)
{
    int end_pos = str_res.find("-----END CMS-----");
    int start_pos = 48;
    int length_res = end_pos - start_pos;
    return str_res.substr(start_pos, length_res);
}

string CWrapper_PKCS11::cmsSignedDataCreate(X509* cert, unsigned char* data, unsigned int data_len, unsigned int* cms_signed_data_len)
{
    OpenSSL_add_all_algorithms();
    PKCS7* p7 = getPkcs7Object();
    PKCS7_SIGNED* p7s = getPkcs7SignedObject(p7, cert);
    PKCS7_SIGNER_INFO* p7si = getPkcs7SignerInfoObject(cert);

    unsigned int md_len;
    unsigned char md_data[EVP_MAX_MD_SIZE];
    getHashData(data, data_len, md_data, &md_len);

    ASN1_STRING* seq = getSignerAttribute(p7si, md_data, md_len);

    unsigned int md_len2;
    unsigned char md_data2[EVP_MAX_MD_SIZE];
    getHashData(seq->data, seq->length, md_data2, &md_len2);

    X509_ALGOR* alg = X509_ALGOR_new();
    unsigned int alg_len = getAlgorithmLen(alg);

    ASN1_OCTET_STRING* digest = ASN1_OCTET_STRING_new();
    unsigned int digest_len = getDigestLen(digest, md_data2, md_len2);

    unsigned int digestInfo_len;
    unsigned char* digestInfo_buf = getDigestInfoBuffer(alg, alg_len, digest, digest_len, &digestInfo_len);

    CK_ULONG sign_data_len;
    unsigned char* sign_data;
    string str_result = signByPkcs11(digestInfo_buf, digestInfo_len, &sign_data, &sign_data_len);
    if (str_result != "")
        return str_result;

    setSignerToPkcs7Object(p7, p7si, sign_data, sign_data_len);
    createContentinfo(p7s, data, data_len);
    unsigned char* cms_signed_data = getCmsSignedData(p7, cms_signed_data_len);

    return getSubstrFinalCms(getFinalCms(cms_signed_data, *cms_signed_data_len));
}

void CWrapper_PKCS11::createContentinfo(PKCS7_SIGNED* p7s, unsigned char* data, size_t data_len)
{
    ASN1_OCTET_STRING* ostr = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(ostr, (unsigned char*)data, data_len);

    PKCS7* p7 = PKCS7_new();
    ASN1_OBJECT* oid = OBJ_txt2obj("1.2.840.113549.1.9.15", 1);
    p7->type = OBJ_dup(oid);
    p7->d.other = ASN1_TYPE_new();
    p7->d.other->type = V_ASN1_OCTET_STRING;
    p7->d.other->value.octet_string = ostr;
    p7s->contents = p7;
}

string CWrapper_PKCS11::signByPkcs11(unsigned char* data, int data_len, unsigned char** signedData, CK_ULONG* signedDataLength)
{
    CK_OBJECT_HANDLE hKey;
    getPrivateKeyHandle(&hKey);
    CK_MECHANISM mechanism = { CKM_RSA_PKCS, NULL_PTR, 0 };
    CK_RV rv = pFunctionList->C_SignInit(hSession, &mechanism, hKey);
    if (rv != CKR_OK)
        return "error";

    rv = pFunctionList->C_Sign(hSession, data, data_len, NULL, signedDataLength);
    if (rv != CKR_OK)
        return "error";

    *signedData = new unsigned char[*signedDataLength];
    rv = pFunctionList->C_Sign(hSession, data, data_len, *signedData, signedDataLength);
    if (rv != CKR_OK)
        return "error";

    return "";
}

CK_ULONG CWrapper_PKCS11::getPrivateKeyHandle(CK_OBJECT_HANDLE* hObject)
{
    CK_OBJECT_CLASS classType = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE objTemplate[] = { { CKA_CLASS, &classType, sizeof(classType)} };

    return findPkcs11Object(hObject, objTemplate, sizeof(objTemplate) / sizeof(CK_ATTRIBUTE));
}

CK_ULONG CWrapper_PKCS11::getCertificateObjectHandle(CK_OBJECT_HANDLE* hObject)
{
    CK_OBJECT_CLASS obj_Pub = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE  obj_Cert = CKC_X_509;
    CK_ATTRIBUTE objTemplate[] = {
        {CKA_CLASS, &obj_Pub, sizeof(obj_Pub)},
        {CKA_CERTIFICATE_TYPE, &obj_Cert, sizeof(obj_Cert)}
    };

    return findPkcs11Object(hObject, objTemplate, sizeof(objTemplate) / sizeof(CK_ATTRIBUTE));
}

CK_ULONG CWrapper_PKCS11::findPkcs11Object(CK_OBJECT_HANDLE* hObject, CK_ATTRIBUTE* objTemplate, int attr_count)
{
    CK_ULONG rv = pFunctionList->C_FindObjectsInit(hSession, objTemplate, attr_count);
    if (rv != CKR_OK)
        return rv;

    CK_OBJECT_HANDLE			foundObjects[10];
    CK_ULONG					numberOfObjects = 10;
    rv = pFunctionList->C_FindObjects(hSession, foundObjects, sizeof(foundObjects), &numberOfObjects);
    if (rv != CKR_OK)
        return 1;

    rv = pFunctionList->C_FindObjectsFinal(hSession);
    if (rv != CKR_OK)
        return 1;

    if (numberOfObjects == 0)
        return 1;

    *hObject = foundObjects[0];
    return 0;
}

CK_ULONG CWrapper_PKCS11::getCertificateAttribute(CK_OBJECT_HANDLE* hObject, CK_ATTRIBUTE* dataTemplate)
{
    CK_ULONG rv = pFunctionList->C_GetAttributeValue(hSession, *hObject, dataTemplate, (unsigned long)1);
    if (rv != CKR_OK)
        return rv;

    if (dataTemplate[0].ulValueLen == 0)
        return CKR_BUFFER_TOO_SMALL;

    dataTemplate[0].pValue = new CK_BYTE[dataTemplate[0].ulValueLen];
    rv = pFunctionList->C_GetAttributeValue(hSession, *hObject, dataTemplate, (unsigned long)1);
    if (rv != CKR_OK)
        return CKR_ATTRIBUTE_VALUE_INVALID;

    return CKR_OK;
}