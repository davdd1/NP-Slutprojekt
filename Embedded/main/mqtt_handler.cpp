#include "mqtt_handler.h"
#include "mqtt_client.h"
#include "print_helper.h"
#include "nvs_handler.h"
#include <iostream>
#include <string>

static int reconnectCounter = 0;

constexpr char *BROKER_COMMON_NAME = "mosquitto";

MQTTHandler::MQTTHandler()
{
    PRINTF_MQTT("MQTTHandler constructor");
    this->params = new mqtt_init_params_t();
    EventGroupHandle_t mqttEventGroup = xEventGroupCreate();
    setEventGroup(&mqttEventGroup);
    // setClientID();
}

MQTTHandler::~MQTTHandler()
{
}

static void mqtt_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    PRINTF_MQTT("MQTT event handler called");

    // Check if arg is valid before dereferencing
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

    switch (event_id)
    {
    case MQTT_EVENT_CONNECTED:
        PRINTF_MQTT("Connected to MQTT broker");
        PRINTF_MQTT("Broker: mqtts://%s", params->brokerURI);
        // PRINTF_MQTT("Client ID: %s", params->clientID);
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
        PRINTF_MQTT("MQTT subscribe");
        break;
    default:
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

    char *ca_cert = (char *)malloc(CERT_SIZE + 1);
    char *client_cert = (char *)malloc(CERT_SIZE + 1);
    char *client_key = (char *)malloc(CERT_SIZE + 1);
    memset(ca_cert, 0, CERT_SIZE + 1);
    memset(client_cert, 0, CERT_SIZE + 1);
    memset(client_key, 0, CERT_SIZE + 1);
    size_t ca_size = CERT_SIZE, cert_size = CERT_SIZE, key_size = CERT_SIZE;

    if (!ca_cert || !client_cert || !client_key)
    {
        PRINTF_MQTT("Failed to allocate memory for certificates");
        free(ca_cert);
        free(client_cert);
        free(client_key);
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
    if (!nvs.loadFromNVS("ca_cert", &ca_cert, &ca_size))
    {
        free(ca_cert);
        return;
    }

    ca_size = strlen(ca_cert) + 1;
    cert_size = strlen(client_cert) + 1;
    key_size = strlen(client_key) + 1;

    PRINTF_MQTT("CA cert: %s", ca_cert);
    PRINTF_MQTT("Client cert: %s", client_cert);
    PRINTF_MQTT("Client key: %s", client_key);

    PRINTF_MQTT("CA cert size: %d bytes", ca_size);
    PRINTF_MQTT("Client cert size: %d bytes", cert_size);
    PRINTF_MQTT("Client key size: %d bytes", key_size);

    esp_mqtt_client_config_t mqttConfig = {};
    std::string uri = "mqtts://" + std::string(CONFIG_MQTT_BROKER_URI) + ":" + std::to_string(8883);
    PRINTF_MQTT("URI: %s", uri.c_str());
    mqttConfig.broker.address.uri = uri.c_str();
    mqttConfig.broker.verification.certificate = (const char*)ca_cert;
    mqttConfig.broker.verification.certificate_len = ca_size;
    mqttConfig.credentials.authentication.certificate = (const char*)client_cert;
    mqttConfig.credentials.authentication.certificate_len = cert_size;
    mqttConfig.credentials.authentication.key = (const char*)client_key;
    mqttConfig.credentials.authentication.key_len = key_size;
    //mqttConfig.broker.address.port = CONFIG_MQTT_BROKER_PORT;
    mqttConfig.network.timeout_ms = 20000;
    mqttConfig.network.reconnect_timeout_ms = 10000;
    mqttConfig.session.keepalive = 60;
    mqttConfig.session.disable_clean_session = true;
    mqttConfig.buffer.size = 2048;
    mqttConfig.buffer.out_size = 2048;
    mqttConfig.task.stack_size = 8192;
    mqttConfig.broker.verification.common_name = "server";
    //mqttConfig.broker.verification.skip_cert_common_name_check = true;
    // Useful?
    // mqtt_cfg.credentials.client_id = std::to_string(deviceId).c_str();

    vTaskDelay(pdMS_TO_TICKS(2000));


    this->params->mqttClient = esp_mqtt_client_init(&mqttConfig);
    if (this->params->mqttClient == NULL)
    {
        PRINTF_MQTT("Failed to initialize MQTT client");
        free(ca_cert);
        free(client_cert);
        free(client_key);
    }

    esp_err_t err = esp_mqtt_client_start(this->params->mqttClient);
    if (err != ESP_OK) {
        PRINTF_MQTT("Failed to start MQTT client: %s", esp_err_to_name(err));
        free(ca_cert);
        free(client_cert);
        free(client_key);
        return;
    }
    ESP_ERROR_CHECK(esp_mqtt_client_register_event(this->params->mqttClient, MQTT_EVENT_ANY, mqtt_event_handler, this->params));
    ESP_ERROR_CHECK(esp_mqtt_client_start(this->params->mqttClient));

    subscribe("/torget");
    subscribe("/spelare/" + std::string(playerID) + "/downlink");
    subscribe("/myndigheten");

    free(ca_cert);
    free(client_cert);
    free(client_key);
}

void MQTTHandler::publishMessage(const std::string &topic, const std::string &message)
{
    publish(topic, message);
}

void MQTTHandler::subscribe(const std::string &topic)
{
}

void MQTTHandler::setEventGroup(EventGroupHandle_t *eventGroup)
{
    this->params->mqttEventGroup = *eventGroup;
}

void MQTTHandler::setBrokerURI()
{
}

void MQTTHandler::setClientID(const std::string &clientID)
{
}

void MQTTHandler::onPlayerMessage(const char* topic, const char* message) {
    // Handle messages from the open forum or players' uplinks
}

void MQTTHandler::onAuthorityMessage(const char* message) {
    // Handle server broadcast messages (e.g., new round, sabotage, etc.)
}

void MQTTHandler::onLeaderElection(const char* message) {
    // Handle leader election decisions (e.g., send "ok" or "neka")
}

void MQTTHandler::onMissionResult(const char* message) {
    // Handle mission success or sabotage outcomes
}

EventGroupHandle_t MQTTHandler::getEventGroup()
{
    return this->params->mqttEventGroup;
}
