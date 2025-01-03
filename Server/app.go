package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"
    "github.com/eclipse/paho.mqtt.golang"
)

const (
	caCertFile = "cert/rootCA.crt"
	caKeyFile  = "cert/rootCA.key"
)

// Paths till serverns cert, för HTTPS:
const (
	serverCertFile = "cert/server.crt"
	serverKeyFile  = "cert/server.key"
)

// Globala variabler för CA i minnet
var (
	caCert *x509.Certificate
	caKey  *rsa.PrivateKey
)

// init() körs innan main(), laddar CA från fil
func init() {
	// 1) Läs CA-cert
	caCertPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		log.Fatalf("Failed to read CA cert file: %v", err)
	}
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		log.Fatal("Failed to parse CA cert PEM")
	}
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse CA cert: %v", err)
	}
	caCert = c

	// 2) Läs CA-nyckel
	caKeyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		log.Fatalf("Failed to read CA key file: %v", err)
	}
	blockKey, _ := pem.Decode(caKeyPEM)
	if blockKey == nil {
		log.Fatal("Failed to parse CA key PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blockKey.Bytes)
	if err != nil {
		log.Fatalf("Failed to parse CA key: %v", err)
	}
	caKey = k.(*rsa.PrivateKey)
}

// createPlayerHandler - exempel på endpoint som skapar ny "spelare"
func createPlayerHandler(w http.ResponseWriter, r *http.Request) {
	// I en riktig lösning kanske du genererar en ny ID från en databas eller räknare.
	// Här hårdkodar vi "id: 5" som demo.
	resp := map[string]any{"id": 5}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// signCertHandler - tar emot en CSR, signerar den med Root CA
func signCertHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}

	// Läs hela body
	csrPEM, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "cannot read body", http.StatusBadRequest)
		return
	}

	// PEM-dekoda CSR
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		http.Error(w, "not a valid CSR PEM", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		http.Error(w, "invalid CSR", http.StatusBadRequest)
		return
	}

	// Verifiera CSR-signatur
	if err := csr.CheckSignature(); err != nil {
		http.Error(w, "CSR signature invalid", http.StatusBadRequest)
		return
	}

	// Skapa "template" för det nya certet
	serialNumber := big.NewInt(time.Now().UnixNano())
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      csr.Subject, // Tar Subjekt (CN, O, m.m.) från CSR
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour), // 1 år

		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, // klientcert
		BasicConstraintsValid: true,
	}

	// Signera certet med vår root CA
	signedCertBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, csr.PublicKey, caKey)
	if err != nil {
		http.Error(w, "failed to create cert", http.StatusInternalServerError)
		return
	}

	// PEM-encoda det nya certet
	var certPem bytes.Buffer
	pem.Encode(&certPem, &pem.Block{Type: "CERTIFICATE", Bytes: signedCertBytes})

	// Skriv tillbaka PEM i svaret
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(certPem.Bytes())
}


func testMQTTConnection() {
	// 1) Ladda root CA för att verifiera Mosquitto-serverns cert
	caCertData, err := os.ReadFile("cert/rootCA.crt")
	if err != nil {
		log.Fatalf("Error reading rootCA: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertData) {
		log.Fatal("Failed to append CA cert")
	}
	
	// 2) Skapa en tls.Config med vår CA-pool
	tlsConfig := &tls.Config{
		RootCAs: caPool,
		// Om Mosquitto inte kräver klientcert, räcker detta.
		// Om du kör mutual TLS kan du lägga in client cert här.
		InsecureSkipVerify: true, // annars måste servern heta samma CN som i certet
	}
	
	// 3) Bygg MQTT ClientOptions
	opts := mqtt.NewClientOptions()
	// Byt ut "mqtts://Jesper:8883" om Mosquitto-cert har CN=Jesper + hosts-filen
	// Annars "mqtts://localhost:8883" om du genererat CN=localhost.
	opts.AddBroker("mqtts://localhost:8884")
	opts.SetClientID("GoClient")
	opts.SetTLSConfig(tlsConfig) // här sätter vi vår Root CA
	
	// 4) Skapa MQTT-client och anslut
	client := mqtt.NewClient(opts)
	token := client.Connect()
	token.Wait()
	if token.Error() != nil {
		log.Fatalf("MQTT connect error: %v", token.Error())
	}
	log.Println("MQTT connected OK")
	
	// 5) Publicera en test-sträng
	pubToken := client.Publish("test", 0, false, "Hello from Go!")
	pubToken.Wait()
	if pubToken.Error() != nil {
		log.Printf("publish error: %v", pubToken.Error())
		} else {
			log.Println("published OK to topic 'test'")
		}
		
		// 6) Stäng anslutning
		client.Disconnect(250)
	}
	
	func main() {
		// Registrera handlers
		http.HandleFunc("/spelare", createPlayerHandler)
		http.HandleFunc("/spelare/csr", signCertHandler)
	
		// Skapa en TLS-server
		srv := &http.Server{
			Addr: ":8884", // t.ex. port 9191
			// Standard Handler = DefaultServeMux (som vi registrerat endpoints på)
		}
	
		// Testa MQTT-anslutning
		//testMQTTConnection()
	
		log.Println("Starting Go server on https://localhost:8884")
		// Starta HTTPS. server.crt/server.key ska vara signerat av rootCA eller en intermediate CA
		log.Fatal(srv.ListenAndServeTLS(serverCertFile, serverKeyFile))
	}