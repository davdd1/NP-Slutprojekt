#pragma once

#include <string>
#include "mqtt_handler.h"

class UARTHandler
{
public:
    UARTHandler();
    ~UARTHandler();

    void init(MQTTHandler *mqttHandler);
    void send(const std::string &message);
    void receive();

private:
    MQTTHandler *mqttHandler;
    char* playerID = nullptr;
};

void uartTask(void *pvParameters);
