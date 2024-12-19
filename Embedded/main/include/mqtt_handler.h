#pragma once

#include <string>
#include "mqtt_client.h"

class MQTTHandler
{
public:
    MQTTHandler();
    ~MQTTHandler();
    

    void init();
    void connect();
    void disconnect();
    void publish(const std::string& topic, const std::string& message);
    void subscribe(const std::string& topic);
    void handleMessage(esp_mqtt_event_t event);

private:
    esp_mqtt_client_handle_t mqttClient;
};