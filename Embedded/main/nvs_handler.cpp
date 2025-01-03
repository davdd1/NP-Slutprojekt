#include "nvs_handler.h"
#include "nvs_flash.h"
#include "print_helper.h"
#include <cstring>

nvsHandler::nvsHandler(const char *partitionName, const char *namespaceName)
    : handle(NULL), partitionName(partitionName), namespaceName(namespaceName)
{
}

nvsHandler::~nvsHandler()
{
    if (handle != NULL)
    {
        nvs_close(handle);
        handle = NULL;
    }
}

bool nvsHandler::init()
{
    esp_err_t nvs_err = nvs_flash_init_partition(partitionName);
    if (nvs_err == ESP_ERR_NVS_NO_FREE_PAGES || nvs_err == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        PRINTF_NVS("Failed to initialize '%s' NVS partition: %s", partitionName, esp_err_to_name(nvs_err));
        return false;
    }
    else if (nvs_err != ESP_OK)
    {
        PRINTF_NVS("Error initializing '%s' NVS partition: %s", partitionName, esp_err_to_name(nvs_err));
        return false;
    }
    return true;
}

bool nvsHandler::openHandle()
{
    if (handle != NULL)
    {
        return true;
    }
    esp_err_t nvsResult = nvs_open_from_partition(partitionName, namespaceName, NVS_READWRITE, &handle);
    if (nvsResult != ESP_OK)
    {
        PRINTF_NVS("nvs_open_from_partition failed for namespace %s: %s", namespaceName, esp_err_to_name(nvsResult));
        return false;
    }
    return true;
}

bool nvsHandler::saveCertificate(const char* certData)
{
    return saveToNVS(CERT_CERTIFICATE, certData, strlen(certData));
}

bool nvsHandler::savePrivateKey(const char* keyData)
{
    return saveToNVS(CERT_PRIVATE_KEY, keyData, strlen(keyData));
}

bool nvsHandler::saveToNVS(const char* key, const char* data, size_t dataSize)
{
    if (!openHandle())
    {
        PRINTF_NVS("Failed to open NVS handle for saving data with key: %s", key);
        return false;
    }

    esp_err_t nvsResult = nvs_set_blob(handle, key, data, dataSize);
    if (nvsResult != ESP_OK)
    {
        PRINTF_NVS("Error writing data to NVS with key '%s': %s", key, esp_err_to_name(nvsResult));
        return false;
    }

    nvsResult = nvs_commit(handle);
    if (nvsResult != ESP_OK)
    {
        PRINTF_NVS("Error committing NVS data with key '%s': %s", key, esp_err_to_name(nvsResult));
        return false;
    }
    return true;
}

bool nvsHandler::loadCertificate(char** certData, size_t* certSize)
{
    return loadFromNVS(CERT_CERTIFICATE, certData, certSize);
}

bool nvsHandler::loadPrivateKey(char** keyData, size_t* keySize)
{
    return loadFromNVS(CERT_PRIVATE_KEY, keyData, keySize);
}

bool nvsHandler::loadFromNVS(const char* key, char** data, size_t* dataSize)
{
    if (!openHandle())
    {
        PRINTF_NVS("Failed to open NVS handle for loading data with key: %s", key);
        return false;
    }

    esp_err_t nvsResult = nvs_get_blob(handle, key, NULL, dataSize);
    if (nvsResult != ESP_OK)
    {
        PRINTF_NVS("Error getting data size from NVS with key '%s': %s", key, esp_err_to_name(nvsResult));
        return false;
    }

    *data = (char *)malloc(*dataSize);
    if (*data == NULL)
    {
        PRINTF_NVS("Memory allocation failed for data with key '%s'", key);
        return false;
    }

    nvsResult = nvs_get_blob(handle, key, *data, dataSize);
    if (nvsResult != ESP_OK)
    {
        PRINTF_NVS("Error reading data from NVS with key '%s': %s", key, esp_err_to_name(nvsResult));
        free(*data);
        return false;
    }
    return true;
}

bool nvsHandler::eraseCertificate()
{
    return eraseFromNVS(CERT_CERTIFICATE);
}

bool nvsHandler::erasePrivateKey()
{
    return eraseFromNVS(CERT_PRIVATE_KEY);
}

bool nvsHandler::eraseFromNVS(const char* key)
{
    if (!openHandle())
    {
        PRINTF_NVS("Failed to open NVS handle for erasing data with key: %s", key);
        return false;
    }

    esp_err_t nvsResult = nvs_erase_key(handle, key);
    if (nvsResult != ESP_OK)
    {
        PRINTF_NVS("Error erasing data from NVS with key '%s': %s", key, esp_err_to_name(nvsResult));
        return false;
    }

    nvsResult = nvs_commit(handle);
    if (nvsResult != ESP_OK)
    {
        PRINTF_NVS("Error committing NVS after erasing data with key '%s': %s", key, esp_err_to_name(nvsResult));
        return false;
    }
    return true;
}
