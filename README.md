# Secret Agents Project

This project enables secure communication between an **ESP32** embedded client and a **Go** server using **MQTT** and **HTTPS**. The system leverages **TLS/SSL** for secure communication and certificate-based authentication.

## Table of Contents
- [Project Overview](#project-overview)
- [Server Side](#server-side)
- [Embedded Client Side](#embedded-client-side)
- [Certificate Management](#certificate-management)
- [License](#license)

## Project Overview

The **Secret Agents** project is designed to securely connect an **ESP32** embedded client with a **Go** server using **MQTT** for communication. The project focuses on ensuring data security and client authentication through **TLS/SSL** encryption.

The server authenticates clients using **client certificates** and uses **CSR (Certificate Signing Request)** to sign client certificates for secure communication. The project also implements a basic **HTTPS server** that handles client requests for CSR signing and interacts with the MQTT broker.

### Key Features:
- **TLS/SSL Encryption**: Ensures that all communication between the embedded client and the server is securely encrypted.
- **CSR Signing**: The server signs **CSR** requests from clients, allowing them to obtain valid certificates for secure communication.
- **Client Authentication**: The server verifies the authenticity of the embedded clients using certificates signed by the root CA.
- **MQTT Communication**: Enables messaging between the client and the server using the MQTT protocol, which is well-suited for low-bandwidth, high-latency environments like IoT devices.

## Server Side

The **Go** server handles multiple roles in this project:
- **TLS/SSL Encryption**: It ensures encrypted communication using certificates, with client certificates validated against a trusted root CA.
- **CSR Signing**: Clients send a CSR to the server, and the server signs it, allowing the client to authenticate securely in future communications.
- **MQTT Broker**: The server can act as an MQTT broker, allowing clients to exchange messages securely over the MQTT protocol.
  
The server listens for HTTPS requests, processes the CSR, and signs it using the **root CA certificate**. The server also ensures that any connected client presents a valid certificate before allowing communication.

### Important Components:
- **Gin Framework**: A fast HTTP web framework used to handle incoming requests for CSR signing.
- **x509 Package**: Utilized to parse and validate certificates and CSRs, and to sign new client certificates.
- **TLS Configuration**: The server uses a custom **TLS configuration** to require client certificates and enforce strict security measures.

## Embedded Client Side

The **ESP32** embedded client is the device that communicates with the server using **MQTT** and **TLS/SSL**. It connects to the server and exchanges messages over a secure channel established with client certificates.

- The **ESP32** client generates a **CSR**, which is sent to the server for signing. The signed certificate is then used by the client to authenticate itself in future communications.
- The **MQTT** protocol is used to send and receive messages. The client connects to the server over **MQTT over TLS**, ensuring the integrity and confidentiality of the data.

### Client Tasks:
- **Generate CSR**: The client generates a **CSR** with its public key and sends it to the server for signing.
- **Authenticate**: Upon receiving the signed certificate, the client can use it for future **mutual authentication** during communication with the server.
- **Secure MQTT Communication**: The client connects to the server's MQTT broker using **TLS** for encrypted messaging.

## Certificate Management

Certificates are a critical part of the security architecture of this system. The server and client use **X.509 certificates** to establish mutual trust and secure communication channels. The main components are:

- **Root CA Certificate**: The **root certificate authority** is used to sign both the server and client certificates, ensuring their authenticity. It needs to be flashed to the NVS of the ESP32.
- **Server Certificate**: This certificate is used by the server to identify itself to the client and establish a secure connection.
- **Client Certificate**: Clients use their certificates to authenticate themselves to the server.
- **Certificate Signing Request (CSR)**: The client sends a CSR to the server for certificate signing. The server signs it with the root CA.

**OpenSSL** is typically used to generate and manage certificates. The server uses **X.509** format for certificates, and the certificates are exchanged in **PEM** format, which is suitable for human-readable files.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
