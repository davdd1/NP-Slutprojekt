#include "wifi_handler.h"
#include "uart_handler.h"
#include "mqtt_handler.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

extern "C" void app_main(void) {
    EventGroupHandle_t wifiEventGroup = xEventGroupCreate();
    wifi_init_params_t wifiParams = {
        .wifiEventGroup = wifiEventGroup,
        .ssid = CONFIG_WIFI_SSID,
        .password = CONFIG_WIFI_PASSWORD
    };
    WiFiHandler wifiHandler(&wifiParams);
    wifiHandler.init();
    wifiHandler.connect();
}