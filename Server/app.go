package main

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
)


const (
	caCertFile     = "cert/rootCA.crt" // Path to CA cert
	caKeyFile      = "cert/rootCA.key" // Path to CA key (if needed, though usually just CA cert is needed)
	serverCertFile = "cert/server.crt" // Path to server cert
	serverKeyFile  = "cert/server.key" // Path to server key
)

// init() will be called before main() to initialize server and certificates
func init() {

	log.Println("Initializing Go server...")

	// Load server certificate and key
	serverCert, err := tls.LoadX509KeyPair(serverCertFile, serverKeyFile)
	if err != nil {
		log.Fatalf("Failed to load server cert/key: %v", err)
	}

	certPool := x509.NewCertPool()
	// Read the CA certificate
	caCert, err := os.ReadFile(caCertFile)
	if err != nil {
		log.Fatalf("Failed to read CA cert file: %v", err)
	}

	// Create a cert pool and append the CA cert for client verification
	certPool.AppendCertsFromPEM(caCert)

	// Create TLS config with CA for client certificate verification
	tlsConfig := &tls.Config{
		ClientCAs:          certPool,                      // The CA cert pool to verify the client certificates
		ClientAuth:         tls.VerifyClientCertIfGiven,   // Require client certificates and verify them
		Certificates:       []tls.Certificate{serverCert}, // Server certificate for the server side of the TLS connection
		InsecureSkipVerify: true,                          // Set to false to ensure strict validation (turn to true for a more lenient check)
	}

	router := gin.Default()
	// Enable logger middleware
	router.Use(gin.Logger())
	router.POST("/spelare/csr", HandleSignCSR)
	router.POST("/spelare", playerIDHandler)

	// Create the HTTP server with the configured TLS settings
	server := &http.Server{
		Addr:      ":9191",   // Define server listening port
		TLSConfig: tlsConfig, // Use the TLS config
		Handler:   router,    // Use the router as the handler
	}

		// Start the HTTPS server
		log.Println("Starting Go server on https://localhost:9191")
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatalf("Failed to start HTTPS server: %v", err)
		}
}

// Handler for creating CSR and returning the signed certificate
// TODO: Make sure only one cert per player ID
func HandleSignCSR(c *gin.Context) {
	// IMPORTANT: Common name is the player ID, only one cert per player ID

	// Expect the client to send CSR data in the request body
	log.Printf("Received Content-Type: %s", c.Request.Header.Get("Content-Type"))

	csrData, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Printf("Error reading CSR data: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to read CSR"})
		return
	}

	if len(csrData) == 0 {
		log.Println("Empty CSR data")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Empty CSR data"})
		return
	}

	// Decode the CSR
	block, _ := pem.Decode(csrData)
	if block == nil {
		log.Println("Failed to decode CSR PEM")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid CSR format"})
		return
	}

	// Parse the CSR
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		log.Printf("Failed to parse CSR: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse CSR"})
		return
	}

	// Ensure CSR is signed by the client
	if err := csr.CheckSignature(); err != nil {
		log.Printf("CSR signature check failed: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid CSR signature"})
		return
	}

	// DEBUG
	log.Printf("CSR Subject: %v", csr.Subject.String())
	log.Printf("CSR DNS Names: %v", csr.DNSNames)
	log.Printf("CSR IP Addresses: %v", csr.IPAddresses)
	log.Printf("CSR Common Name: %v", csr.Subject.CommonName)

	// Load the CA certificate and key
	caCertPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		log.Printf("Failed to read CA cert file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read CA cert"})
		return
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		log.Println("Failed to decode CA cert PEM")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode CA cert"})
		return
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		log.Printf("Failed to parse CA cert: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse CA cert"})
		return
	}
	caKeyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		log.Printf("Failed to read CA key file: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read CA key"})
		return
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		log.Println("Failed to decode CA key PEM")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode CA key"})
		return
	}
	var caKey interface{}
	switch caKeyBlock.Type {
	case "RSA PRIVATE KEY":
		caKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
		if err != nil {
			log.Printf("Failed to parse RSA private key: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse RSA private key"})
			return
		}
	case "EC PRIVATE KEY":
		caKey, err = x509.ParseECPrivateKey(caKeyBlock.Bytes)
		if err != nil {
			log.Printf("Failed to parse EC private key: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse EC private key"})
			return
		}
	case "PRIVATE KEY":
		caKey, err = x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
		if err != nil {
			log.Printf("Failed to parse PKCS8 private key: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse PKCS8 private key"})
			return
		}
	default:
		log.Printf("Unknown private key type: %v", caKeyBlock.Type)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Unknown private key type"})
		return
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		log.Printf("Failed to generate serial number: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate serial number"})
		return
	}

	// Create the signed client certificate based on the CSR
	certTemplate := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // Valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Sign the certificate with the CA private key
	derBytes, err := x509.CreateCertificate(
		rand.Reader,
		certTemplate,
		caCert,
		csr.PublicKey,
		caKey,
	)
	if err != nil {
		log.Printf("Failed to create certificate: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to sign certificate"})
		return
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if certPEM == nil {
		log.Println("Failed to encode certificate to PEM")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode certificate"})
		return
	}

	parsedCert, err := x509.ParseCertificate(derBytes)
	if err != nil {
		log.Printf("Failed to parse signed certificate: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse signed certificate"})
		return
	}
	log.Printf("Signed certificate subject: %s\n", parsedCert.Subject.String())
	log.Printf("Signed certificate common name: %s\n", parsedCert.Subject.CommonName)

	log.Printf("Certificate signed successfully\n")
	c.Data(http.StatusOK, "application/x-pem-file", certPEM)
}

// Give a player ID to a new player, same id for same player
func givePlayerID() string {
	// temp
	// TODO: Implement a way to give a player ID
	// RAndom number as a string with rand function
	// For now just return a random number
	// return strconv.Itoa(rand.Intn(1000))
	return "321"

}

// Handler for creating a new player ID, need to remember this ID for the player, cant gen
func playerIDHandler(c *gin.Context) {
	playerID := givePlayerID()

	// Prepare the response
	response := gin.H{"id": playerID}

	// Log the response
	log.Printf("Response sent: %v", response)

	c.Header("Content-Type", "application/json; charset=utf-8")

	// Send the response
	c.JSON(http.StatusOK, response)
}

func main() {
	log.Println("Starting Go server...")

}
