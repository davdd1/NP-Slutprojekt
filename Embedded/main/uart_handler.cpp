#include "uart_handler.h"
#include "print_helper.h"
#include "mqtt_handler.h"
#include "nvs_handler.h"
#include <driver/uart.h>
#include <string>
#include "cJSON.h"

#define UART_PORT_NUM UART_NUM_0
#define UART_TX_PIN 1
#define UART_RX_PIN 3
#define UART_BUF_SIZE 2048

UARTHandler::UARTHandler() {}

UARTHandler::~UARTHandler() {
    if (playerID != nullptr) {
        free(playerID);
    }
}

void UARTHandler::init(MQTTHandler *mqttHandler)
{
    PRINTF_UART("Initializing UART");
    this->mqttHandler = mqttHandler;
    ESP_ERROR_CHECK(uart_driver_install(UART_PORT_NUM, UART_BUF_SIZE, 0, 0, NULL, 0));
}

void UARTHandler::send(const std::string &message)
{
    PRINTF_UART("Sending message: %s", message.c_str());

    // Load playerID from NVS
    if (playerID == nullptr)
    {
        nvsHandler nvs("eol", "certs");
        if (!nvs.init())
        {
            PRINTF_UART("Failed to initialize NVS");
            return;
        }
        size_t playerID_len = 0;
        if (!nvs.loadFromNVS("player_id", &playerID, &playerID_len))
        {
            PRINTF_UART("Failed to load player ID from NVS");
            return;
        }
    }

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

    // Check that it's one of: /torget, /spelare/<playerID>/uplink
    if (topic == "/torget")
    {
        // /torget message, format as { "id": "<playerID>", "meddelande": "<msg>" }
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "id", playerID);
        cJSON_AddStringToObject(root, "meddelande", msg.c_str());
        char *json = cJSON_Print(root);
        if (json)
        {
            msg = json;
            cJSON_free(json);
        }
        cJSON_Delete(root);
    }
    else if (topic.starts_with("/spelare/") && topic.ends_with("/uplink"))
    {
        // Extrahera playerID från topic
        auto player_id_start = topic.find("/spelare/") + 9; // Början av playerID
        auto player_id_end = topic.rfind("/uplink");        // Slutet av playerID

        std::string playerID_topic = topic.substr(player_id_start, player_id_end - player_id_start);

        // Kontrollera om playerID matchar
        if (playerID != playerID_topic)
        {
            PRINTF_UART("Unauthorized topic: %s\nYou tried to send 'ID=%s' when your ID is %s", topic.c_str(), playerID_topic.c_str(), playerID);
            return;
        }

        // Formatera meddelandet som JSON
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "val", msg.c_str());
        if (char *json = cJSON_PrintUnformatted(root)) // Använd kompakt JSON
        {
            msg = json;
            cJSON_free(json);
        }
        cJSON_Delete(root);
    }
    else
    {
        PRINTF_UART("Invalid topic: %s", topic.c_str());
        return;
    }

    // Publish message to MQTT
    mqttHandler->publishMessage(topic, msg);
}

void UARTHandler::receive()
{
    char data[UART_BUF_SIZE];
    int len = uart_read_bytes(UART_PORT_NUM, data, UART_BUF_SIZE, pdMS_TO_TICKS(1000));
    if (len > 0)
    {
        data[len] = '\0'; // Null terminate safely
        PRINTF_UART("Received data: %s", data);
        send(std::string(data));
    }
    else if (len < 0)
    {
        PRINTF_UART("Failed to read data from UART");
    }
    else if (len == 0)
    {
        return;
    }
    else
    {
        PRINTF_UART("Received data is too large or failed to read.");
    }
}

void uartTask(void *pvParameters)
{
    PRINTF_UART("Starting UART task");

    nvsHandler nvs("eol", "certs");
    if (!nvs.init())
    {
        PRINTF_UART("Failed to initialize NVS");
        vTaskDelete(NULL);
        return;
    }
    size_t playerID_len = 0;
    char *playerID = nullptr;
    if (!nvs.loadFromNVS("player_id", &playerID, &playerID_len))
    {
        PRINTF_UART("Failed to load player ID from NVS");
        vTaskDelete(NULL);
        return;
    }
    if (playerID == nullptr)
    {
        PRINTF_UART("Player ID is NULL");
        vTaskDelete(NULL);
        return;
    }
    PRINTF_UART("Game Player ID: %s", playerID);

    UARTHandler *uartHandler = (UARTHandler *)pvParameters;

    while (true)
    {
        uartHandler->receive();
    }
}
