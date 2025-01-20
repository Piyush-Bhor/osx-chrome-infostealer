package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

// AES 256-bit key
const key = "F\x9b^\x90\x1dK\t\x14\xae\xe4R\xf9\xbfl\xd4\n\x17}\xeb\xa9E\xean\n\xa7{N\x8f\xc3:\x19M"

// Handle the incoming POST request for uploading data
func handlePost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Read the request body
	ciphertextBase64, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusInternalServerError)
		logError("Failed to read request body", err)
		return
	}
	defer r.Body.Close()

	// Decode the base64 input
	ciphertext, err := base64.StdEncoding.DecodeString(string(ciphertextBase64))
	if err != nil {
		http.Error(w, "Failed to decode base64 data", http.StatusBadRequest)
		logError("Failed to decode base64 data", err)
		return
	}

	// Decrypt the data
	plaintext, err := decryptAES(ciphertext, []byte(key))
	if err != nil {
		http.Error(w, "Failed to decrypt data", http.StatusInternalServerError)
		logError("Failed to decrypt data", err)
		return
	}

	// Write the decrypted data to a YAML file
	outputFile := "output.yaml"
	if err := os.WriteFile(outputFile, plaintext, 0644); err != nil {
		http.Error(w, "Failed to write to file", http.StatusInternalServerError)
		logError("Failed to write to file", err)
		return
	}

	// Respond to the client
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Data successfully written to output.yaml"))
}

// Decrypt the given ciphertext using AES-256 in GCM mode
func decryptAES(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// AES-GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Separate the nonce and the actual ciphertext
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, err
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// Log errors to a file
func logError(message string, err error) {
	timestamp := time.Now().Format(time.RFC3339)
	logMessage := timestamp + " - " + message + ": " + err.Error() + "\n"
	logFilePath := "error_log.txt"
	file, fileErr := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if fileErr != nil {
		log.Fatalf("Error opening log file: %v", fileErr)
		return
	}
	defer file.Close()
	_, fileErr = file.WriteString(logMessage)
	if fileErr != nil {
		log.Fatalf("Failed to write to log file: %v", fileErr)
	}
}

// Handle the incoming POST request for reporting errors
func reportError(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	// Read the error report data
	errorData, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read error report", http.StatusInternalServerError)
		logError("Failed to read error report", err)
		return
	}
	defer r.Body.Close()

	// Log the error report
	logError("Reported Error: "+string(errorData), nil)

	// Respond to the client
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Error report received and logged"))
}

func main() {
	// Set up the HTTP server
	http.HandleFunc("/upload", handlePost)        // Handle the main data upload
	http.HandleFunc("/report_error", reportError) // Handle error reports
	port := ":8080"
	log.Printf("Server running on http://localhost%s", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
