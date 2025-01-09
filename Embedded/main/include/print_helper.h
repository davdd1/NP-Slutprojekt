#pragma once

#include <cstdio>

// Define color codes
#define RED "\033[31m"
#define GREEN "\033[32m"
#define YELLOW "\033[33m"
#define BLUE "\033[34m"
#define MAGENTA "\033[35m"
#define CYAN "\033[36m"
#define RESET "\033[0m"

#define PRINTF_COLOR(color, format, ...) printf("%s" format "%s", color, ##__VA_ARGS__, RESET)

#define PRINTF_MAIN(format, ...) \
    PRINTF_COLOR(RED, "Main: "); \
    printf(format, ##__VA_ARGS__); \
    printf("\n")
#define PRINTF_MQTT(format, ...) \
    PRINTF_COLOR(BLUE, "MQTT: "); \
    printf(format, ##__VA_ARGS__); \
    printf("\n")
#define PRINTF_UART(format, ...) \
    PRINTF_COLOR(GREEN, "UART: "); \
    printf(format, ##__VA_ARGS__); \
    printf("\n")
#define PRINTF_WIFI(format, ...) \
    PRINTF_COLOR(MAGENTA, "WiFi: "); \
    printf(format, ##__VA_ARGS__); \
    printf("\n")
#define PRINTF_NVS(format, ...) \
    PRINTF_COLOR(YELLOW, "NVS: "); \
    printf(format, ##__VA_ARGS__); \
    printf("\n")
#define PRINTF_HTTPS(format, ...) \
    PRINTF_COLOR(CYAN, "HTTPS: "); \
    printf(format, ##__VA_ARGS__); \
    printf("\n")

