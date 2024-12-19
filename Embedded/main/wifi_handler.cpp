#include "wifi_handler.h"
#include "print_helper.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "esp_system.h"
#include "esp_event.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"

static int reconnectCounter = 0;

WiFiHandler::WiFiHandler() {
    PRINTF_WIFI("WiFiHandler constructor");
    this->params = new wifi_init_params_t();
    EventGroupHandle_t wifiEventGroup = xEventGroupCreate();
    setEventGroup(wifiEventGroup);
    setSSID(CONFIG_WIFI_SSID);
    setPassword(CONFIG_WIFI_PASSWORD);
    this->init();
    this->connect();
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
        case WIFI_EVENT_STA_CONNECTED:
            PRINTF_WIFI("WiFi connected");
            xEventGroupSetBits(params->wifiEventGroup, WIFI_CONNECTED_BIT);
            break;
        case WIFI_EVENT_STA_DISCONNECTED:
            PRINTF_WIFI("WiFi disconnected");
            xEventGroupClearBits(params->wifiEventGroup, WIFI_CONNECTED_BIT | WIFI_HAS_IP_BIT);
            if (reconnectCounter < WIFI_RECONNECT_MAX_ATTEMPT) {
                reconnectCounter++;
                esp_wifi_connect();
            }
            break;
        default:
            break;
    }
}

static void ip_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    PRINTF_WIFI("IP event handler called");

    wifi_init_params_t* params = (wifi_init_params_t*)arg;

    switch (event_id) {
        case IP_EVENT_STA_GOT_IP: {
            PRINTF_WIFI("Got IP");
            xEventGroupSetBits(params->wifiEventGroup, WIFI_HAS_IP_BIT);    
            break;
        } 
        default: {
            PRINTF_WIFI("Unhandled IP event ID: %ld", event_id);
            break;  
        }
    }
}

void WiFiHandler::init() {
    PRINTF_WIFI("Init WiFi");
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_t* netif = esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    ESP_ERROR_CHECK(esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, this->params, NULL));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &ip_event_handler, this->params, NULL));

    wifi_config_t wifi_config = {0};
    memcpy(wifi_config.sta.ssid, this->params->ssid, sizeof(this->params->ssid));
    memcpy(wifi_config.sta.password, this->params->password, sizeof(this->params->password));

    wifi_config.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    wifi_config.sta.pmf_cfg.capable = true;    
    wifi_config.sta.pmf_cfg.required = false;    

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
}

void WiFiHandler::connect() {
    PRINTF_WIFI("Connect to WiFi");
    PRINTF_WIFI("SSID: %s", this->params->ssid);
    PRINTF_WIFI("Password: %s", this->params->password);
    PRINTF_WIFI("Event group: %p", this->params->wifiEventGroup);
    PRINTF_WIFI("Event group bits: %ld", xEventGroupGetBits(this->params->wifiEventGroup));
    PRINTF_WIFI("CONFIG_WIFI_SSID: %s", CONFIG_WIFI_SSID);
    PRINTF_WIFI("CONFIG_WIFI_PASSWORD: %s", CONFIG_WIFI_PASSWORD);
    esp_wifi_connect();
}

void WiFiHandler::disconnect() {
    PRINTF_WIFI("Disconnect from WiFi");
    esp_wifi_disconnect();
}

bool WiFiHandler::isConnected() {
    PRINTF_WIFI("Check if WiFi is connected");
    return xEventGroupGetBits(this->params->wifiEventGroup) & WIFI_HAS_IP_BIT;
}

void WiFiHandler::setSSID(char* ssid) {
    PRINTF_WIFI("Set WiFi SSID");
    strncpy(this->params->ssid, ssid, sizeof(this->params->ssid) - 1);
    this->params->ssid[sizeof(this->params->ssid) - 1] = '\0';
}

void WiFiHandler::setPassword(char* password) {
    PRINTF_WIFI("Set WiFi password");
    strncpy(this->params->password, password, sizeof(this->params->password) - 1);
    this->params->password[sizeof(this->params->password) - 1] = '\0';
}

void WiFiHandler::setEventGroup(EventGroupHandle_t eventGroup) {
    PRINTF_WIFI("Set WiFi event group");
    this->params->wifiEventGroup = eventGroup;
}
