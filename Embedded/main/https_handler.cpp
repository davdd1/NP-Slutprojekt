#include "https_handler.h"
#include "print_helper.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/oid.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/pem.h"
#include "nvs_handler.h"
#include "cJSON.h"

#define CERT_SIZE 2048

HTTPSHandler::HTTPSHandler(const std::string &serverURL)
    : ca_cert(nullptr), signed_cert(nullptr), private_key(nullptr), ca_size(0), signed_cert_size(0), private_key_size(0),
      csr_data(nullptr), client(nullptr), serverURL(serverURL), playerID(-1), handler(this)
{
}

HTTPSHandler::~HTTPSHandler()
{
    if (ca_cert)
    {
        free(ca_cert);
    }
    if (signed_cert)
    {
        free(signed_cert);
    }
    if (private_key)
    {
        free(private_key);
    }
    if (client)
    {
        esp_http_client_cleanup(client);
    }

    if (httpsEventGroup)
    {
        xEventGroupClearBits(httpsEventGroup, HAS_CSR_BIT | HAS_PLAYER_ID_BIT | HAS_SIGNED_CERT_BIT | HTTPS_READY_BIT);
        vEventGroupDelete(httpsEventGroup);
    }

    if (response.buffer)
    {
        free(response.buffer);
    }

    if (csr_data)
    {
        free(csr_data);
    }
}

bool HTTPSHandler::init()
{

    nvsHandler nvs("eol", "certs");
    if (!nvs.init())
    {
        PRINTF_HTTPS("Failed to initialize NVS");
        free(ca_cert);
        return false;
    }

    if (!nvs.loadFromNVS("ca_cert", &ca_cert, &ca_size))
    {
        PRINTF_HTTPS("Failed to load CA certificate from NVS");
        free(ca_cert);
        return false;
    }

    return true;
}

esp_err_t HTTPSHandler::http_event_handler(esp_http_client_event_t *evt)
{
    HTTPSHandler *handler = (HTTPSHandler *)evt->user_data;
    if (!handler)
    {
        return ESP_ERR_INVALID_ARG;
    }

    switch (evt->event_id)
    {
    case HTTP_EVENT_DISCONNECTED:
        PRINTF_HTTPS("HTTP_EVENT_DISCONNECTED");
        handler->response.len = 0;
        break;
    case HTTP_EVENT_ERROR:
        PRINTF_HTTPS("HTTP_EVENT_ERROR");
        break;
    case HTTP_EVENT_ON_CONNECTED:
        PRINTF_HTTPS("HTTP_EVENT_ON_CONNECTED");
        break;
    case HTTP_EVENT_HEADER_SENT:
        PRINTF_HTTPS("HTTP_EVENT_HEADER_SENT");
        break;
    case HTTP_EVENT_ON_HEADER:
        PRINTF_HTTPS("HTTP_EVENT_ON_HEADER, key=%s, value=%s", evt->header_key, evt->header_value);
        break;
    case HTTP_EVENT_REDIRECT:
        PRINTF_HTTPS("HTTP_EVENT_REDIRECT");
        break;
    case HTTP_EVENT_ON_DATA:
        PRINTF_HTTPS("HTTP_EVENT_ON_DATA, len=%d", evt->data_len);
        if (!evt->data)
            break;
        if (evt->data_len > 0)
        {
            // Check if there's enough space in the buffer
            if ((handler->response.len + evt->data_len) > MAX_HTTP_OUTPUT_BUFFER)
            {
                // Reallocate buffer to accommodate the new data
                size_t new_size = handler->response.len + evt->data_len;
                char *new_buffer = (char *)realloc(handler->response.buffer, new_size);

                // Check if realloc was successful
                if (new_buffer != nullptr)
                {
                    handler->response.buffer = new_buffer;
                }
                else
                {
                    PRINTF_HTTPS("Failed to reallocate buffer for new data.");
                    return ESP_FAIL;
                }
            }

            // Append new data to the buffer
            memcpy(handler->response.buffer + handler->response.len, evt->data, evt->data_len);
            handler->response.len += evt->data_len;
        }

        break;
    case HTTP_EVENT_ON_FINISH:
        PRINTF_HTTPS("HTTP_EVENT_ON_FINISH");

        esp_http_client *client = evt->client;
        if (client)
        {
            int status_code = esp_http_client_get_status_code(client);
            if (status_code == 200)
            {
                std::string responseStr(handler->response.buffer, handler->response.len);
                if (responseStr.find("-----BEGIN CERTIFICATE-----") != std::string::npos)
                {
                    PRINTF_HTTPS("Certificate received");

                    handler->storeSignedCertificate(responseStr.c_str());
                    free(handler->response.buffer);
                }
                else
                {
                    int playerID = handler->extractPlayerID(responseStr.c_str());
                    if (playerID != -1)
                    {
                        handler->playerID = playerID;
                        PRINTF_HTTPS("Player registered successfully with ID: %d", handler->playerID);
                        xEventGroupSetBits(handler->httpsEventGroup, HAS_PLAYER_ID_BIT);
                    }
                    else
                    {
                        PRINTF_HTTPS("Unexpected response format: %s", responseStr.c_str());
                    }
                }
            }
            else
            {
                PRINTF_HTTPS("Unexpected status code: %d", status_code);
            }
        }
        handler->response.len = 0;
        break;
    }
    return ESP_OK;
}

int HTTPSHandler::registerPlayer()
{
    std::string payload = "";
    response.buffer = (char *)malloc(MAX_HTTP_OUTPUT_BUFFER + 1);
    if (!response.buffer)
    {
        PRINTF_HTTPS("Failed to allocate memory for response buffer");
        return -1;
    }
    memset(response.buffer, 0, MAX_HTTP_OUTPUT_BUFFER + 1);
    response.len = 0;

    std::string fullURL = serverURL + "/spelare";
    esp_http_client_config_t config = {
        .url = fullURL.c_str(),
        .cert_pem = ca_cert,
        .timeout_ms = 10000,
        .event_handler = http_event_handler,
        .user_data = this, // User data passed to event handler
        .skip_cert_common_name_check = true,
    };

    esp_http_client *clientPlayer = esp_http_client_init(&config);
    if (!clientPlayer)
    {
        PRINTF_HTTPS("Failed to initialize HTTP client for player registration");
        free(response.buffer);
        return -1;
    }

    esp_http_client_set_method(clientPlayer, HTTP_METHOD_POST);
    esp_http_client_set_post_field(clientPlayer, payload.c_str(), payload.length());

    esp_err_t err = esp_http_client_perform(clientPlayer);
    if (err != ESP_OK)
    {
        PRINTF_HTTPS("Failed to perform HTTP request for player registration: %s", esp_err_to_name(err));
        esp_http_client_cleanup(clientPlayer);
        free(response.buffer);
        return -1;
    }

    int status_code = esp_http_client_get_status_code(clientPlayer);
    int content_len = esp_http_client_get_content_length(clientPlayer);
    PRINTF_HTTPS("HTTP Status Code: %d", status_code);

    if (content_len <= 0)
    {
        PRINTF_HTTPS("No valid response received from server");
        esp_http_client_cleanup(clientPlayer);
        free(response.buffer);
        return -1;
    }

    // Wait for player ID to be extracted from response
    while (playerID == -1)
    {
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    PRINTF_HTTPS("Player registered with ID: %d", playerID);
    esp_http_client_cleanup(clientPlayer);
    return playerID;
}

int HTTPSHandler::extractPlayerID(const std::string &response)
{
    cJSON *root = cJSON_Parse(response.c_str());
    if (!root)
    {
        PRINTF_HTTPS("Failed to parse JSON response");
        return -1;
    }

    cJSON *jsonID = cJSON_GetObjectItem(root, "id");
    if (!jsonID)
    {
        PRINTF_HTTPS("Missing player ID from JSON response");
        cJSON_Delete(root);
        return -1;
    }

    int id = -1;
    if (cJSON_IsNumber(jsonID))
    {
        id = jsonID->valueint;
    }
    else if (cJSON_IsString(jsonID))
    {
        id = atoi(jsonID->valuestring);
        if (id == 0 && jsonID->valuestring[0] != '0')
        {
            PRINTF_HTTPS("Invalid player ID string: %s", jsonID->valuestring);
            cJSON_Delete(root);
            return -1;
        }
    }
    else
    {
        PRINTF_HTTPS("Invalid player ID format");
        cJSON_Delete(root);
        return -1;
    }

    playerID = id;
    PRINTF_HTTPS("Player ID has been set to: %d", playerID);

    cJSON_Delete(root);
    return id;
}

bool HTTPSHandler::generateCSR(int playerID)
{
    int ret;

    if (playerID <= 0)
    {
        PRINTF_HTTPS("Player ID is empty, cannot generate CSR");
        return false;
    }

    // Initialize the random number generator and load the CA certificate
    mbedtls_pk_context key;
    mbedtls_x509write_csr csr;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    mbedtls_pk_init(&key);
    mbedtls_x509write_csr_init(&csr);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    const char *pers_string = "STI";
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers_string, strlen(pers_string)) != 0)
    {
        PRINTF_HTTPS("Failed to seed random number generator");
        mbedtls_pk_free(&key);
        mbedtls_x509write_csr_free(&csr);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    // Generate RSA key pair
    ret = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
    if (ret != 0)
    {
        PRINTF_HTTPS("Failed to set up RSA key pair:-0x%04x", -ret);
        mbedtls_pk_free(&key);
        mbedtls_x509write_csr_free(&csr);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    ret = mbedtls_rsa_gen_key(mbedtls_pk_rsa(key), mbedtls_ctr_drbg_random, &ctr_drbg, 2048, 65537);
    if (ret != 0)
    {
        PRINTF_HTTPS("Failed to generate RSA key:-0x%04x", -ret);
        mbedtls_pk_free(&key);
        mbedtls_x509write_csr_free(&csr);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    unsigned char keyBuf[2048];
    memset(keyBuf, 0, sizeof(keyBuf));

    ret = mbedtls_pk_write_key_pem(&key, keyBuf, sizeof(keyBuf));
    if (ret != 0)
    {
        PRINTF_HTTPS("Failed to write private key in PEM format: %d", ret);
        mbedtls_pk_free(&key);
        mbedtls_x509write_csr_free(&csr);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    private_key = (char *)malloc(strlen((char *)keyBuf) + 1);
    if (!private_key)
    {
        PRINTF_HTTPS("Failed to allocate memory for private key");
        mbedtls_pk_free(&key);
        mbedtls_x509write_csr_free(&csr);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return false;
    }
    strcpy(private_key, (char *)keyBuf);
    private_key_size = strlen(private_key);
    private_key[strlen((char *)keyBuf)] = '\0';

    char subjectName[64];
    snprintf(subjectName, sizeof(subjectName), "CN=%d", playerID);
    PRINTF_HTTPS("%s", subjectName);
    ret = mbedtls_x509write_csr_set_subject_name(&csr, subjectName);
    if (ret != 0)
    {
        PRINTF_HTTPS("Failed to set subject name in CSR:-0x%04x", -ret);
        free(private_key);
        return false;
    }

    PRINTF_HTTPS("Private key: %s", private_key);
    PRINTF_HTTPS("Private key length: %d", strlen(private_key));
    PRINTF_HTTPS("Private key size: %d", private_key_size);

    // parse_key needs pk context to be reset
    mbedtls_pk_free(&key);
    mbedtls_pk_init(&key);

    ret = mbedtls_pk_parse_key(&key, (const unsigned char *)private_key, private_key_size + 1, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0)
    {
        PRINTF_HTTPS("Failed to parse private key:-0x%04x", -ret);
        free(private_key);
        mbedtls_pk_free(&key);
        mbedtls_x509write_csr_free(&csr);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    mbedtls_x509write_csr_set_md_alg(&csr, MBEDTLS_MD_SHA256);
    mbedtls_x509write_csr_set_key(&csr, &key);

    unsigned char csr_buf[CSR_BUF_SIZE];
    memset(csr_buf, 0, CSR_BUF_SIZE);
    size_t csr_len = sizeof(csr_buf);
    ret = mbedtls_x509write_csr_pem(&csr, csr_buf, CSR_BUF_SIZE, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret < 0)
    {
        PRINTF_HTTPS("Failed to write CSR in PEM format: %d", ret);
        free(private_key);
        mbedtls_pk_free(&key);
        mbedtls_x509write_csr_free(&csr);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    nvsHandler nvs("eol", "certs");
    if (!nvs.init())
    {
        PRINTF_HTTPS("Failed to initialize NVS");
        free(private_key);
        mbedtls_pk_free(&key);
        mbedtls_x509write_csr_free(&csr);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return false;
    }
    if (!nvs.savePrivateKey(private_key))
    {
        PRINTF_HTTPS("Failed to save private key to NVS");
        free(private_key);
        mbedtls_pk_free(&key);
        mbedtls_x509write_csr_free(&csr);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    csr_data = (char *)malloc(csr_len + 1);
    if (!csr_data)
    {
        PRINTF_HTTPS("Failed to allocate memory for CSR");
        free(private_key);
        mbedtls_pk_free(&key);
        mbedtls_x509write_csr_free(&csr);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        return false;
    }

    memcpy(csr_data, csr_buf, csr_len);
    csr_data[csr_len] = '\0';

    xEventGroupSetBits(handler->httpsEventGroup, HAS_CSR_BIT);

    free(private_key);
    mbedtls_pk_free(&key);
    mbedtls_x509write_csr_free(&csr);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return true;
}

std::string HTTPSHandler::sendCSRAndReceiveCertificate()
{
    response.buffer = (char *)malloc(MAX_HTTP_OUTPUT_BUFFER + 1);
    if (!response.buffer)
    {
        PRINTF_HTTPS("Failed to allocate memory for response buffer");
        return "";
    }
    memset(response.buffer, 0, MAX_HTTP_OUTPUT_BUFFER + 1);
    response.len = 0;
    std::string uri = "/spelare/csr";
    std::string fullURL = serverURL + uri;
    esp_http_client_config_t config = {
        .url = fullURL.c_str(),
        .cert_pem = ca_cert,
        .event_handler = http_event_handler,
        .user_data = this,
        .skip_cert_common_name_check = true,
    };

    esp_http_client *clientCSR = esp_http_client_init(&config);
    if (!clientCSR)
    {
        PRINTF_HTTPS("Failed to initialize HTTP client for CSR");
        free(response.buffer);
        return "";
    }

    esp_http_client_set_header(clientCSR, "Content-Type", "application/pkcs8");
    esp_http_client_set_method(clientCSR, HTTP_METHOD_POST);
    esp_http_client_set_post_field(clientCSR, csr_data, strlen(csr_data));

    esp_err_t err = esp_http_client_perform(clientCSR);
    if (err != ESP_OK)
    {
        PRINTF_HTTPS("Failed to perform HTTP request for CSR: %s", esp_err_to_name(err));
        esp_http_client_cleanup(clientCSR);
        free(response.buffer);
        return "";
    }

    int status_code = esp_http_client_get_status_code(clientCSR);
    int content_len = esp_http_client_get_content_length(clientCSR);
    PRINTF_HTTPS("HTTP Status Code: %d", status_code);

    if (content_len <= 0)
    {
        PRINTF_HTTPS("No valid response received from server");
        esp_http_client_cleanup(clientCSR);
        free(response.buffer);
        return "";
    }

    vTaskDelay(pdMS_TO_TICKS(100));

    if (response.len == 0)
    {
        PRINTF_HTTPS("No valid response received.");
        esp_http_client_cleanup(clientCSR);
        free(response.buffer);
        return "";
    }

    while (response.len == 0)
    {
        vTaskDelay(pdMS_TO_TICKS(10));
    }

    esp_http_client_cleanup(clientCSR);
    return "";
}

bool HTTPSHandler::storeSignedCertificate(const char *certData)
{
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int ret = mbedtls_x509_crt_parse(&cert, (const unsigned char *)certData, strlen(certData) + 1);
    if (ret != 0)
    {
        PRINTF_HTTPS("Failed to parse signed certificate: -0x%04x", -ret);
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, sizeof(error_buf));
        PRINTF_HTTPS("Error: %s", error_buf);
        mbedtls_x509_crt_free(&cert);
        return false;
    }

    // Beräkna buffertstorlek för PEM-format och allokera minne
    size_t der_cert_size = cert.raw.len;
    size_t pem_buffer_size = der_cert_size * 5; // Säkerhetsmarginal
    char *pem_cert = (char *)malloc(pem_buffer_size);
    if (!pem_cert)
    {
        PRINTF_HTTPS("Failed to allocate memory for signed certificate");
        mbedtls_x509_crt_free(&cert);
        return false;
    }

    size_t pem_cert_len = 0;
    ret = mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n",
                                   "-----END CERTIFICATE-----\n",
                                   cert.raw.p, cert.raw.len,
                                   (unsigned char *)pem_cert, pem_buffer_size,
                                   &pem_cert_len);
    if (ret != 0)
    {
        PRINTF_HTTPS("Failed to write signed certificate in PEM format: -0x%04x", -ret);
        free(pem_cert);
        mbedtls_x509_crt_free(&cert);
        return false;
    }

    if (pem_cert_len < pem_buffer_size)
    {
        pem_cert[pem_cert_len] = '\0';
    }
    else
    {
        PRINTF_HTTPS("PEM certificate length reached buffer size, cannot null-terminate safely");
        free(pem_cert);
        mbedtls_x509_crt_free(&cert);
        return false;
    }

    nvsHandler nvs("eol", "certs");
    if (!nvs.init())
    {
        PRINTF_HTTPS("Failed to initialize NVS");
        free(pem_cert);
        mbedtls_x509_crt_free(&cert);
        return false;
    }

    vTaskDelay(pdMS_TO_TICKS(100));

    if (!nvs.saveCertificate(pem_cert))
    {
        PRINTF_HTTPS("Failed to save signed certificate to NVS");
        free(pem_cert);
        mbedtls_x509_crt_free(&cert);
        return false;
    }

    free(pem_cert);
    mbedtls_x509_crt_free(&cert);
    xEventGroupSetBits(handler->httpsEventGroup, HAS_SIGNED_CERT_BIT);
    return true;
}

std::string HTTPSHandler::startGame()
{
    std::string payload = "{\"val\": \"nu kör vi\"}";

    std::string fullURL = serverURL + "/start";
    esp_http_client_config_t config = {
        .url = fullURL.c_str(),
        .cert_pem = ca_cert,
        .event_handler = http_event_handler,
        .user_data = this,
        .skip_cert_common_name_check = true,
    };

    esp_http_client *clientGame = esp_http_client_init(&config);
    if (!clientGame)
    {
        PRINTF_HTTPS("Failed to initialize HTTP client for game start");
        return "";
    }

    esp_http_client_set_header(clientGame, "Content-Type", "application/json");
    esp_http_client_set_method(clientGame, HTTP_METHOD_POST);
    esp_http_client_set_post_field(clientGame, payload.c_str(), payload.length());

    esp_err_t err = esp_http_client_perform(clientGame);
    if (err != ESP_OK)
    {
        PRINTF_HTTPS("Failed to perform HTTP request for game start: %s", esp_err_to_name(err));
        esp_http_client_cleanup(clientGame);
        return "";
    }

    int status_code = esp_http_client_get_status_code(clientGame);
    int content_len = esp_http_client_get_content_length(clientGame);
    PRINTF_HTTPS("HTTP Status Code: %d", status_code);

    if (content_len <= 0)
    {
        PRINTF_HTTPS("No valid response received from server");
        esp_http_client_cleanup(clientGame);
        return "";
    }

    // Dont know if there will be a response
    // std::string responseStr(response.buffer, response.len);
    // esp_http_client_cleanup(clientGame);
    // return responseStr;

    return "";
}

void httpsTask(void *pvParameters)
{
    EventGroupHandle_t eventGroup = (EventGroupHandle_t)pvParameters;
    std::string url = CONFIG_HTTPS_SERVER_URI;
    HTTPSHandler *httpsHandler = new HTTPSHandler(url);
    httpsHandler->httpsEventGroup = eventGroup;
    if (!httpsHandler->init())
    {
        PRINTF_HTTPS("Failed to initialize HTTPS handler.");
        vTaskDelete(NULL);
        return;
    }

    int playerID = httpsHandler->registerPlayer();
    xEventGroupWaitBits(httpsHandler->getEventGroup(), HAS_PLAYER_ID_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
    PRINTF_HTTPS("Player ID: %d", playerID);

    // Incase of failure, retry registration
    while (playerID == -1)
    {
        vTaskDelay(pdMS_TO_TICKS(5000));
        playerID = httpsHandler->registerPlayer();
        PRINTF_HTTPS("Player ID: %d", playerID);
    }

    nvsHandler nvs("eol", "certs");
    if (!nvs.init())
    {
        PRINTF_HTTPS("Failed to initialize NVS");
        vTaskDelete(NULL);
        return;
    }
    if (!nvs.saveToNVS("player_id", std::to_string(playerID).c_str(), sizeof(playerID)))
    {
        PRINTF_HTTPS("Failed to save player ID to NVS");
        vTaskDelete(NULL);
        return;
    }

    httpsHandler->generateCSR(playerID);
    xEventGroupWaitBits(httpsHandler->getEventGroup(), HAS_CSR_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
    httpsHandler->sendCSRAndReceiveCertificate();
    xEventGroupWaitBits(httpsHandler->getEventGroup(), HAS_SIGNED_CERT_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    xEventGroupSetBits(httpsHandler->getEventGroup(), HTTPS_READY_BIT);

    // httpsHandler->startGame();

    while (true)
    {
        vTaskDelay(pdMS_TO_TICKS(2000));
    }

    vTaskDelete(NULL);
}