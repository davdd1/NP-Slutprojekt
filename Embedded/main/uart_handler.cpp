#include "uart_handler.h"
#include <driver/uart.h>
#include "print_helper.h"

#define UART_PORT_NUM UART_NUM_0
#define UART_TX_PIN 1
#define UART_RX_PIN 3
#define UART_BUF_SIZE 1024

UARTHandler::UARTHandler() {}

UARTHandler::~UARTHandler() {}

void UARTHandler::init()
{
    PRINTF_UART("Initializing UART");

    ESP_ERROR_CHECK(uart_driver_install(UART_PORT_NUM, UART_BUF_SIZE, 0, 0, NULL, 0));
}

void UARTHandler::send(const std::string &message)
{
    PRINTF_UART("Sending message: %s", message.c_str());
    uart_write_bytes(UART_PORT_NUM, message.c_str(), message.size());
}

void UARTHandler::receive()
{
    char data[UART_BUF_SIZE];
    int len = uart_read_bytes(UART_PORT_NUM, data, sizeof(data), pdMS_TO_TICKS(1000));
    if (len > 0) {
        data[len] = '\0';
        PRINTF_UART("Received data: %s", data);
    }
}
