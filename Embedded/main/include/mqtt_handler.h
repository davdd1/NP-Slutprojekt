#pragma once

#include <string>
#include "mqtt_client.h"

#define MQTT_CONNECTED_BIT BIT4
#define MQTT_RECONNECT_MAX_ATTEMPT 5

typedef struct
{
    EventGroupHandle_t mqttEventGroup;
    esp_mqtt_client_handle_t mqttClient;
} mqtt_init_params_t;

class MQTTHandler
{
public:
    MQTTHandler();
    ~MQTTHandler();

    void init();
    void publishMessage(const std::string &topic, const std::string &message);
    void setClientID(const std::string &clientID);
    void setEventGroup(EventGroupHandle_t *eventGroup);
    void setBrokerURI();
    void handleMessage(esp_mqtt_event_t event);
    EventGroupHandle_t getEventGroup();

    void onPlayerMessage(const char *topic, const char *message);
    void onAuthorityMessage(const char *message);
    void onLeaderElection(const char *message);
    void onMissionResult(const char *message);

    void subscribe(const std::string &topic);

private:
    mqtt_init_params_t *params;
    char *playerID;
};