#pragma once

#include <string>

class UARTHandler
{
public:
    UARTHandler();
    ~UARTHandler();

    void init();
    void send(const std::string &message);
    void receive();
};
