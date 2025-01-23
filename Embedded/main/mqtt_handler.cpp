#include "mqtt_handler.h"
#include "mqtt_client.h"
#include "print_helper.h"
#include "nvs_handler.h"
#include <string>
#include "mqtt_client.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/oid.h"
#include "mbedtls/error.h"
#include "mbedtls/pk.h"
#include "mbedtls/pem.h"
#include "mbedtls/x509_csr.h"
#include "mbedtls/x509.h"
#include "mbedtls/entropy.h"
#include "mbedtls/x509_crt.h"

static int reconnectCounter = 0;

MQTTHandler::MQTTHandler()
{
    PRINTF_MQTT("MQTTHandler constructor");
    this->params = new mqtt_init_params_t();
    EventGroupHandle_t mqttEventGroup = xEventGroupCreate();
    setEventGroup(&mqttEventGroup);
}

MQTTHandler::~MQTTHandler()
{
}

static void mqtt_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;

    if (arg == NULL)
    {
        PRINTF_MQTT("Error: mqtt_event_handler called with null arg");
        return;
    }
    mqtt_init_params_t *params = (mqtt_init_params_t *)arg;
    if (params->mqttEventGroup == NULL)
    {
        PRINTF_MQTT("Error: mqttEventGroup is NULL");
        return;
    }

    switch ((esp_mqtt_event_id_t)event_id)
    {
    case MQTT_EVENT_CONNECTED:
        PRINTF_MQTT("Connected to MQTT broker");
        PRINTF_MQTT("Broker: mqtts://%s:%d", CONFIG_MQTT_BROKER_URI, CONFIG_MQTT_BROKER_PORT);
        xEventGroupSetBits(params->mqttEventGroup, MQTT_CONNECTED_BIT);
        break;
    case MQTT_EVENT_DISCONNECTED:
        PRINTF_MQTT("MQTT disconnected");
        xEventGroupClearBits(params->mqttEventGroup, MQTT_CONNECTED_BIT);
        if (reconnectCounter < MQTT_RECONNECT_MAX_ATTEMPT)
        {
            vTaskDelay(pdMS_TO_TICKS(2000));
            reconnectCounter++;
            esp_mqtt_client_reconnect(params->mqttClient);
        }
        break;
    case MQTT_EVENT_SUBSCRIBED:
        PRINTF_MQTT("Subscribe successful");
        break;
    case MQTT_EVENT_DATA:

        char topic[100];
        char data[500];

        // Copy topic and null-terminate
        strncpy(topic, event->topic, event->topic_len);
        topic[event->topic_len] = '\0';

        strncpy(data, event->data, event->data_len);
        data[event->data_len] = '\0';

        // TODO: Handle messages differently from different topics, ex: from /myndigheten // OR Maybe in UARTHandler

        if (event->topic_len > 0 && event->data_len > 0)
        {
            PRINTF_MQTT("Received data from topic '%s': %s", topic, data);
        }
        else 
        {
            PRINTF_MQTT("Error in received data and/or topic");
        }
        break;
    default:
        PRINTF_MQTT("MQTT event: %lud", event_id);
        break;
    }
}

void MQTTHandler::init()
{



    PRINTF_MQTT("Initializing MQTT");
    nvsHandler nvs("eol", "certs");

    if (!nvs.init())
    {
        PRINTF_MQTT("Failed to initialize NVS");
        return;
    }
    size_t playerID_len = 0;
    if (!nvs.loadFromNVS("player_id", &playerID, &playerID_len))
    {
        PRINTF_MQTT("Failed to load player ID from NVS");
        return;
    }

    size_t ca_size = 0, cert_size = 0, key_size = 0;
    char *ca_cert;
    char *client_cert;
    char *client_key;

    if (!nvs.loadFromNVS("ca_cert", &ca_cert, &ca_size))
    {
        free(ca_cert);
        return;
    }
    if (!nvs.loadCertificate(&client_cert, &cert_size))
    {
        free(ca_cert);
        free(client_cert);
        return;
    }

    if (!nvs.loadPrivateKey(&client_key, &key_size))
    {
        free(ca_cert);
        free(client_cert);
        free(client_key);
        return;
    }

    std::string uri = "mqtts://" + std::string(CONFIG_MQTT_BROKER_URI) + ":" + std::to_string(CONFIG_MQTT_BROKER_PORT);
    PRINTF_MQTT("URI: %s", uri.c_str());
    esp_mqtt_client_config_t mqttConfig = {};
    mqttConfig.broker.address.uri = uri.c_str();
    mqttConfig.broker.verification.skip_cert_common_name_check = true;
    mqttConfig.broker.verification.certificate = (const char *)ca_cert;
    mqttConfig.credentials.authentication.certificate = (const char *)client_cert;
    mqttConfig.credentials.authentication.key = (const char *)client_key;
    mqttConfig.credentials.client_id = playerID;

    vTaskDelay(pdMS_TO_TICKS(500));

    this->params->mqttClient = esp_mqtt_client_init(&mqttConfig);
    if (this->params->mqttClient == NULL)
    {
        PRINTF_MQTT("Failed to initialize MQTT client");
        free(ca_cert);
        free(client_cert);
        free(client_key);
    }

    ESP_ERROR_CHECK(esp_mqtt_client_register_event(this->params->mqttClient, MQTT_EVENT_ANY, mqtt_event_handler, this->params));
    ESP_ERROR_CHECK(esp_mqtt_client_start(this->params->mqttClient));

    xEventGroupWaitBits(this->params->mqttEventGroup, MQTT_CONNECTED_BIT, pdFALSE, pdTRUE, portMAX_DELAY);

    subscribe("/torget");
    subscribe("/spelare/" + std::string(playerID) + "/downlink");
    subscribe("/myndigheten");

    free(playerID);
    free(ca_cert);
    free(client_cert);
    free(client_key);
}

void MQTTHandler::publishMessage(const std::string &topic, const std::string &message)
{
    PRINTF_MQTT("Publishing message to topic %s", topic.c_str());
    esp_mqtt_client_publish(this->params->mqttClient, topic.c_str(), message.c_str(), message.size(), 0, 0);
}

void MQTTHandler::subscribe(const std::string &topic)
{
    PRINTF_MQTT("Subscribing to topic %s", topic.c_str());
    esp_mqtt_client_subscribe(this->params->mqttClient, topic.c_str(), 0);
}

void MQTTHandler::setEventGroup(EventGroupHandle_t *eventGroup)
{
    this->params->mqttEventGroup = *eventGroup;
}

void MQTTHandler::handleMessage(esp_mqtt_event_t event)
{
    // PRINT MESSAGE
    PRINTF_MQTT("Received message on topic %s: \n%s", event.topic, event.data);
}

EventGroupHandle_t MQTTHandler::getEventGroup()
{
    return this->params->mqttEventGroup;
}
