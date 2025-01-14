#pragma once

#include <string>

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
};

void uartTask(void *pvParameters);
