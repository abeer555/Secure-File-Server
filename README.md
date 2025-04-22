# Secure File Server

A lightweight HTTP file server with OpenSSL AES-256-CBC encryption for secure file storage and transfer, plus an integrated Intrusion Detection System (IDS) for security monitoring. Files are automatically encrypted on the server and can be decrypted using the provided tools.

![Encryption](https://img.shields.io/badge/Encryption-AES--256--CBC-green)
![Security](https://img.shields.io/badge/Security-IDS%20Monitoring-red)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-blue)
![License](https://img.shields.io/badge/License-MIT-blue)

## Features

- 🔒 **Automatic file encryption** using OpenSSL AES-256-CBC
- 🛡️ **Intrusion Detection System (IDS)** to monitor and block suspicious activities
- 🔑 **Basic authentication** to restrict server access
- 📂 **Intuitive web interface** for browsing files
- 🖼️ **Image preview support** (images remain unencrypted for display)
- 📱 **Responsive design** works on desktop and mobile devices
- 🧵 **Multi-threaded** handling of requests for better performance
- 🔄 **Downloadable encrypted files** with simple decryption script

## Requirements

- Python 3.6+
- OpenSSL command-line tools
- Bash shell (for decryption script)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/abeer555/Secure-File-Server.git
   cd Secure-File-Server
   ```

2. Make the decryption script executable:
   ```bash
   chmod +x decrypt.sh
   ```

## Usage

### Starting the Server

1. Configure the server by editing the settings at the top of the `server.py` file:
   ```python
   PORT = 8001  # Change to your preferred port
   USERNAME = "a"  # Change to your preferred username
   PASSWORD = "a"  # Change to a strong password
   ```

2. Run the server:
   ```bash
   python3 server.py
   ```

3. Access the server at `http://localhost:8001` (or your configured port) through your web browser

### Authentication

- When accessing the server, you'll be prompted for the username and password you configured.
- Default credentials are username: `a`, password: `a`.

### Accessing Files

- Navigate through directories by clicking on folder names
- Download files by clicking on file names
- Files (except images) are automatically encrypted when served

### Intrusion Detection System (IDS)

The server includes a built-in IDS that monitors for suspicious activities:

- **Security Monitoring**: Tracks login attempts, request rates, and suspicious patterns
- **Automatic Blocking**: Blocks IPs after multiple high-severity security events
- **Security Dashboard**: Access at `/ids_dashboard` using your server credentials
- **Real-time Alerts**: Visual indicators when suspicious activities are detected
- **Comprehensive Logging**: All security events are logged with timestamps and details

The IDS is configured to detect:
- Brute force login attempts
- Abnormal request rates (potential DoS)
- Common attack patterns (SQL injection, XSS, path traversal)
- Known malicious user agents

### Decrypting Files

Use the included `decrypt.sh` script to decrypt downloaded files:

```bash
./decrypt.sh path/to/encrypted_file
```

By default, the decrypted file will be saved as `decrypted_file.dat`. The script extracts the initialization vector (IV) from the beginning of the file and uses it along with your encryption key to decrypt the file.

## Security Considerations

- The encryption key is stored in `encryption_key.bin` in the same directory as the server. Protect this file!
- First-time server startup generates a random 256-bit encryption key.
- Change the default username and password before deploying in a production environment.
- This server uses HTTP (not HTTPS), so consider running it behind a reverse proxy with TLS for production use.
- The server is designed for use within trusted networks (LAN/private networks).
- The IDS configuration can be adjusted in the `IDS_CONFIG` section of the code to match your security requirements.

## Server Architecture

- **Encryption System**: Uses OpenSSL AES-256-CBC with a unique IV for each file
- **Metadata Management**: Tracks encrypted files and their original sizes
- **Threading**: Handles multiple connections simultaneously
- **File Management**: Preserves original file structure while storing encrypted versions
- **Intrusion Detection**: Real-time monitoring of requests and user activities

## Troubleshooting

If you encounter issues decrypting files, check that:
- The encryption key file (`encryption_key.bin`) is in the correct location
- OpenSSL is properly installed on your system
- The file was actually encrypted by this server

If you see a high number of security alerts in the IDS dashboard:
- Check for misconfigured clients making repeated requests
- Look for patterns in the blocked requests
- Adjust the IDS thresholds if needed for your environment

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Created by [abeer555](https://github.com/abeer555)
