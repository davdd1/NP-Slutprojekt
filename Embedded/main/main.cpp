#include "wifi_handler.h"
#include "uart_handler.h"
#include "mqtt_handler.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"

extern "C" void app_main(void) {
    WiFiHandler wifiHandler;
}