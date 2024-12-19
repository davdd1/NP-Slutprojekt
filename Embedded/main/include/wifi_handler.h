#pragma once

#include <string>
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_HAS_IP_BIT BIT1
#define WIFI_RECONNECT_MAX_ATTEMPT 50

typedef struct {
    EventGroupHandle_t wifiEventGroup;
    std::string ssid;
    std::string password;
} wifi_init_params_t;

class WiFiHandler {
public:

    WiFiHandler(wifi_init_params_t* params);
    ~WiFiHandler();
    void init();
    void connect();
    void disconnect();
    bool isConnected();
    void setSSID(const std::string &ssid);
    void setPassword(const std::string &password);
private:
    wifi_init_params_t* params;
};