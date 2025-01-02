#include "wifi_handler.h"
#include "uart_handler.h"
#include "mqtt_handler.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "print_helper.h"
#include "esp_heap_caps.h"

WiFiHandler wifiHandler;
MQTTHandler mqttHandler;
UARTHandler uartHandler;

extern "C" void app_main(void) {


    wifiHandler.init();
    uartHandler.init();

    //Check heap
    PRINTF_MAIN("Free heap: %lud", esp_get_free_heap_size());
    heap_caps_print_heap_info(MALLOC_CAP_8BIT);

    xEventGroupWaitBits(wifiHandler.getEventGroup(), WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    mqttHandler.init();

    xEventGroupWaitBits(mqttHandler.getEventGroup(), MQTT_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    mqttHandler.subscribe("test");
    uartHandler.send("Hello from ESP32!\n");

    PRINTF_MAIN("Main finished.");

    while (true) {
        uartHandler.receive();
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}