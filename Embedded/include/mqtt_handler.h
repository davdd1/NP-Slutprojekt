#pragma once

#include <string>

class MQTTHandler
{
public:
    MQTTHandler();
    ~MQTTHandler();
    

    void init();
    void publish(const std::string &topic, const std::string &message);
    void subscribe(const std::string &topic);
};