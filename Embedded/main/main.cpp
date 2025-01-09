#include "wifi_handler.h"
#include "uart_handler.h"
#include "mqtt_handler.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "print_helper.h"
#include "esp_heap_caps.h"
#include "nvs_flash.h"
#include "https_handler.h"

WiFiHandler wifi;
MQTTHandler mqtt;
UARTHandler uart;
EventGroupHandle_t eventGroup;

extern "C" void app_main(void)
{

    wifi.init();
    uart.init();

    xEventGroupWaitBits(wifi.getEventGroup(), WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);
    vTaskDelay(pdMS_TO_TICKS(2000));

    eventGroup = xEventGroupCreate();
    xTaskCreate(httpsTask, "HTTPS Task", HTTPS_TASK_STACK_SIZE, (void*)eventGroup, 5, NULL);

    xEventGroupWaitBits(eventGroup, HTTPS_READY_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    PRINTF_MAIN("Starting MQTT");

    mqtt.init();

    xEventGroupWaitBits(mqtt.getEventGroup(), MQTT_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    PRINTF_MAIN("Main finished.");

    while (true)
    {
        uart.receive();
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}