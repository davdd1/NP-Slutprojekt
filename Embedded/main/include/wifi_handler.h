#pragma once

#include <string>
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"

#define WIFI_CONNECTED_BIT BIT0
#define WIFI_HAS_IP_BIT BIT1
#define WIFI_RECONNECT_MAX_ATTEMPT 50

typedef struct
{
    char ssid[32];
    char password[32];
    EventGroupHandle_t wifiEventGroup;
} wifi_init_params_t;

class WiFiHandler
{
public:
    WiFiHandler();
    ~WiFiHandler();
    void init();
    void disconnect();
    bool isConnected();
    void setSSID(char *ssid);
    void setPassword(char *password);
    void setEventGroup(EventGroupHandle_t eventGroup);
    EventGroupHandle_t getEventGroup();

private:
    wifi_init_params_t *params;
};