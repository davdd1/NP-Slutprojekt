#pragma once

#include <cstdint>
#include <cstddef>
#include "nvs.h"

#define NVS_NAMESPACE_DEFAULT "certs"
#define CERT_CERTIFICATE "client_cert"
#define CERT_PRIVATE_KEY "client_key"
#define NVS_CERT_SAVE_DONE_BIT   BIT6 // Bit for certificate save completion
#define NVS_KEY_SAVE_DONE_BIT    BIT7 // Bit for key save completion
#define NVS_CERT_LOAD_DONE_BIT   BIT8 // Bit for certificate load completion
#define NVS_KEY_LOAD_DONE_BIT    BIT9 // Bit for key load completion

enum CertificateType
{
    FACTORY_CERT = 0,
    CLIENT_CERT = 1
};

class nvsHandler {
public:
    // Constructor with partition and namespace parameters
    nvsHandler(const char *partitionName = NVS_NAMESPACE_DEFAULT, const char *namespaceName = NVS_NAMESPACE_DEFAULT);
    ~nvsHandler();

    bool init();  // Initialize NVS and perform setup tasks
    bool saveCertificate(const char* certData);
    bool savePrivateKey(const char* keyData);
    bool loadCertificate(char** certData, size_t* certSize);
    bool loadPrivateKey(char** keyData, size_t* keySize);
    bool eraseCertificate();
    bool erasePrivateKey();

private:
    bool openHandle(); // Open NVS handle
    bool saveToNVS(const char* key, const char* data, size_t dataSize);
    bool loadFromNVS(const char* key, char** data, size_t* dataSize);
    bool eraseFromNVS(const char* key);

    nvs_handle_t handle;
    const char* partitionName;
    const char* namespaceName;
};
