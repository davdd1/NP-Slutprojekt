#pragma once

#include <string>
#include "mqtt_client.h"

#define MQTT_CONNECTED_BIT BIT4
#define MQTT_RECONNECT_MAX_ATTEMPT 5

typedef struct {
    char brokerURI[64];
    char clientID[32];
    EventGroupHandle_t mqttEventGroup;
    esp_mqtt_client_handle_t mqttClient;
} mqtt_init_params_t;

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
    void setClientID(const std::string &clientID);
    void setEventGroup(EventGroupHandle_t* eventGroup);
    void setBrokerURI();
    void handleMessage(esp_mqtt_event_t event);
    EventGroupHandle_t getEventGroup();

private:
    mqtt_init_params_t* params;
};