#include "uart_handler.h"
#include "print_helper.h"
#include "mqtt_handler.h"
#include <driver/uart.h>
#include <string>
#include "cJSON.h"

#define UART_PORT_NUM UART_NUM_0
#define UART_TX_PIN 1
#define UART_RX_PIN 3
#define UART_BUF_SIZE 1024

UARTHandler::UARTHandler() {}

UARTHandler::~UARTHandler() {}

void UARTHandler::init(MQTTHandler *mqttHandler)
{
    PRINTF_UART("Initializing UART");
    this->mqttHandler = mqttHandler;
    ESP_ERROR_CHECK(uart_driver_install(UART_PORT_NUM, UART_BUF_SIZE, 0, 0, NULL, 0));
}

void UARTHandler::send(const std::string &message)
{
    PRINTF_UART("Sending message: %s", message.c_str());

    // Parse the message and send it to MQTT
    // format: "/topic:message"
    std::string topic = message.substr(0, message.find(":"));
    std::string msg = message.substr(message.find(":") + 1);
    if (topic.empty() || msg.empty())
    {
        PRINTF_UART("Invalid message format: %s", message.c_str());
        return;
    }
    else if (topic[0] != '/')
    {
        PRINTF_UART("Invalid topic format: %s", topic.c_str());
        return;
    }
    // Check that its one of: /torget, /spelare/<playerID>/downlink
    else if (topic != "/torget")
    {
        // Make JSON
        // { "id": "playerID", "message": "msg" }
        cJSON *root = cJSON_CreateObject();
        char *json = cJSON_Print(root);
        cJSON_AddStringToObject(root, "id", "playerID");
        cJSON_AddStringToObject(root, "message", msg.c_str());
        msg = json;
        cJSON_Delete(root);
    }
    else if (topic.find("/spelare/") != std::string::npos && topic.find("/downlink") != std::string::npos)
    {
        // Make JSON
        // { "val": "msg" }
        cJSON *root = cJSON_CreateObject();
        char *json = cJSON_Print(root);
        cJSON_AddStringToObject(root, "val", msg.c_str());
        msg = json;
        cJSON_Delete(root);
    }
    else
    {
        PRINTF_UART("Invalid topic: %s", topic.c_str());
        return;
    }

    mqttHandler->publishMessage(topic, msg);
}

void UARTHandler::receive()
{
    char data[UART_BUF_SIZE];
    int len = uart_read_bytes(UART_PORT_NUM, data, sizeof(data), pdMS_TO_TICKS(1000));
    if (len > 0)
    {
        data[len] = '\0';
        PRINTF_UART("Received data: %s", data);
        send(data);
    }
}

void uartTask(void *pvParameters)
{
    PRINTF_UART("Starting UART task");
    UARTHandler *uartHandler = (UARTHandler *)pvParameters;

    while (true)
    {
        uartHandler->receive();
    }
}
