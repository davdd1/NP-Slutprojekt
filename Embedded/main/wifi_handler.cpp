#include "wifi_handler.h"
#include "print_helper.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "esp_system.h"
#include "esp_event.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"


WiFiHandler::WiFiHandler(wifi_init_params_t* params) {
    PRINTF_WIFI("WiFiHandler constructor");
    this->params = params;
    this->init();
}

WiFiHandler::~WiFiHandler() {
    PRINTF_WIFI("WiFiHandler destructor");
}

static void wifi_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    PRINTF_WIFI("WiFi event handler called");
    wifi_init_params_t* params = (wifi_init_params_t*)arg;
    switch (event_id) {
        case WIFI_EVENT_STA_START:
            esp_wifi_connect();
            break;
        case WIFI_EVENT_STA_DISCONNECTED:
            esp_wifi_connect();
            break;
        default:
            break;
    }
}

static void ip_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    PRINTF_WIFI("IP event handler called");

    wifi_init_params_t* params = (wifi_init_params_t*)arg;

    switch (event_id) {
        case IP_EVENT_STA_GOT_IP: 
            PRINTF_WIFI("IP event handler got IP");
            ip_event_got_ip_t* event = (ip_event_got_ip_t*)event_data;
            PRINTF_WIFI("WiFi connected, IP: %s", ip4addr_ntoa((const ip4_addr_t*)&event->ip_info.ip));
            xEventGroupSetBits(params->wifiEventGroup, WIFI_HAS_IP_BIT);
            break;
        default:
            PRINTF_WIFI("Unhandled IP event ID: %ld", event_id);
            break;  
    }
}

void WiFiHandler::init() {
    PRINTF_WIFI("WiFiHandler init");
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, this->params, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &ip_event_handler, this->params, NULL));

}

void WiFiHandler::connect() {
    PRINTF_WIFI("WiFiHandler connect");
    esp_wifi_connect();
}

void WiFiHandler::disconnect() {
    PRINTF_WIFI("WiFiHandler disconnect");
}

bool WiFiHandler::isConnected() {
    PRINTF_WIFI("WiFiHandler isConnected");
    return false;
}

void WiFiHandler::setSSID(const std::string &ssid) {
    PRINTF_WIFI("WiFiHandler setSSID");
}

void WiFiHandler::setPassword(const std::string &password) {
    PRINTF_WIFI("WiFiHandler setPassword");
}