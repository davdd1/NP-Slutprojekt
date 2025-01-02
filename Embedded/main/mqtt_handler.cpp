#include "mqtt_handler.h"
#include "mqtt_client.h"
#include "print_helper.h"
#include <iostream>
#include <string>

static int reconnectCounter = 0;

static void mqtt_event_handler(esp_mqtt_event_t* event)
{
    printf("MQTT event handler called\n");
}

MQTTHandler::MQTTHandler()
{
    PRINTF_MQTT("MQTTHandler constructor");
    this->params = new mqtt_init_params_t();
    EventGroupHandle_t mqttEventGroup = xEventGroupCreate();
    setEventGroup(&mqttEventGroup);
    setBrokerURI();
    //setClientID();
}

MQTTHandler::~MQTTHandler()
{
}

static void mqtt_event_handler(void* arg, esp_event_base_t event_base, int32_t event_id, void* event_data) {
    PRINTF_MQTT("MQTT event handler called");

    // Check if arg is valid before dereferencing
    if (arg == NULL) {
        PRINTF_MQTT("Error: mqtt_event_handler called with null arg");
        return;
    }
    mqtt_init_params_t* params = (mqtt_init_params_t*)arg;
     if (params->mqttEventGroup == NULL) {
        PRINTF_MQTT("Error: mqttEventGroup is NULL");
        return;
    }

    switch (event_id) {
        case MQTT_EVENT_CONNECTED:
            PRINTF_MQTT("Connected to MQTT broker");
            PRINTF_MQTT("Broker: mqtts://%s", params->brokerURI);
            PRINTF_MQTT("Client ID: %s", params->clientID);
            xEventGroupSetBits(params->mqttEventGroup, MQTT_CONNECTED_BIT);
            break;
        case MQTT_EVENT_DISCONNECTED:
            PRINTF_MQTT("MQTT disconnected");
            xEventGroupClearBits(params->mqttEventGroup, MQTT_CONNECTED_BIT);
            if (reconnectCounter < MQTT_RECONNECT_MAX_ATTEMPT) {
                reconnectCounter++;
                esp_mqtt_client_reconnect(params->mqttClient);
            }
            break;
        case MQTT_EVENT_SUBSCRIBED:
            PRINTF_MQTT("MQTT subscribe");
            break;
        default:
            break;
    }
}

void MQTTHandler::init()
{
    PRINTF_MQTT("MADE IT TO MQTT INIT");
    esp_mqtt_client_config_t mqttConfig = {};
    char fullURI[128];
    snprintf(fullURI, sizeof(fullURI), "mqtts://%s", this->params->brokerURI);
    mqttConfig.broker.address.uri = fullURI;
  
    this->params->mqttClient = esp_mqtt_client_init(&mqttConfig);
    if (this->params->mqttClient == NULL) {
        PRINTF_MQTT("Failed to initialize MQTT client");
        return;
    }
    ESP_ERROR_CHECK(esp_mqtt_client_register_event(this->params->mqttClient, MQTT_EVENT_ANY, mqtt_event_handler, this->params));
    ESP_ERROR_CHECK(esp_mqtt_client_start(this->params->mqttClient));
}

void MQTTHandler::publish(const std::string& topic, const std::string& message)
{
}

void MQTTHandler::subscribe(const std::string& topic)
{
}

void MQTTHandler::setEventGroup(EventGroupHandle_t* eventGroup)
{
    this->params->mqttEventGroup = *eventGroup;
}

void MQTTHandler::setBrokerURI() 
{
    strncpy(this->params->brokerURI, CONFIG_MQTT_BROKER_URI, sizeof(this->params->brokerURI));
}

void MQTTHandler::setClientID(const std::string& clientID)
{
   
}

EventGroupHandle_t MQTTHandler::getEventGroup()
{
    return this->params->mqttEventGroup;
}
