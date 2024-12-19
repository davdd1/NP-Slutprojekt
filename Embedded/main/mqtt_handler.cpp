#include "mqtt_handler.h"
#include "mqtt_client.h"
#include "print_helper.h"

static void mqtt_event_handler(esp_mqtt_event_t* event)
{
    printf("MQTT event handler called\n");
}

MQTTHandler::MQTTHandler()
{
}

MQTTHandler::~MQTTHandler()
{
}

void MQTTHandler::init()
{
}

void MQTTHandler::publish(const std::string& topic, const std::string& message)
{
}

void MQTTHandler::subscribe(const std::string& topic)
{
}
