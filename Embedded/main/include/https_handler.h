#pragma once

#include <string>
#include "lwip/sockets.h"
#include "lwip/netif.h"
#include "esp_http_client.h"
#include "mbedtls/pk.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509_crt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"


#define CSR_BUF_SIZE 4096
#define HAS_PLAYER_ID_BIT BIT10
#define HAS_CSR_BIT BIT11
#define HAS_SIGNED_CERT_BIT BIT12
#define HTTPS_READY_BIT BIT13
#define HTTPS_TASK_STACK_SIZE 14096
#define MAX_HTTP_OUTPUT_BUFFER 4096

typedef struct {
    char *buffer;
    int len;
} http_response_t;


//int* client_id;
void httpsTask(void* pvParameters);

class HTTPSHandler {
public:
    HTTPSHandler(const std::string& serverURL);
    ~HTTPSHandler();

    static esp_err_t http_event_handler(esp_http_client_event_t *evt);

    bool init();

    int registerPlayer();

    int extractPlayerID(const std::string &response);

    bool generateCSR(int playerID);
    std::string sendCSRAndReceiveCertificate();
    bool storeSignedCertificate(const std::string& certData);
    
    std::string startGame();
    EventGroupHandle_t getEventGroup() { return httpsEventGroup; }
    EventGroupHandle_t httpsEventGroup;

private:
    http_response_t response;
    int playerID = -1; 

    char* ca_cert;
    size_t ca_size;
    
    char* signed_cert;
    size_t signed_cert_size;

    char* private_key;
    size_t private_key_size;

    char* csr_data;
    esp_http_client_handle_t client;

    const std::string serverURL;
    HTTPSHandler* handler;


    mbedtls_pk_context key;
    mbedtls_x509write_csr csr;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

};
