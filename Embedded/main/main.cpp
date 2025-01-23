#include "wifi_handler.h"
#include "uart_handler.h"
#include "mqtt_handler.h"
#include "https_handler.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "print_helper.h"

WiFiHandler wifi;
MQTTHandler mqtt;
UARTHandler uart;
EventGroupHandle_t eventGroup;

extern "C" void app_main(void)
{

    wifi.init();
    uart.init(&mqtt);

    xEventGroupWaitBits(wifi.getEventGroup(), WIFI_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    eventGroup = xEventGroupCreate();
    xTaskCreate(httpsTask, "HTTPS Task", HTTPS_TASK_STACK_SIZE, (void *)eventGroup, 5, NULL);

    xEventGroupWaitBits(eventGroup, HTTPS_READY_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    mqtt.init();

    xEventGroupWaitBits(mqtt.getEventGroup(), MQTT_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    xTaskCreate(uartTask, "UART Task", 6000, (void *)&uart, 5, NULL);
}