#!/bin/bash

# Script to decrypt files downloaded from the CN project server.

# --- Configuration ---
KEY_FILE="encryption_key.bin"    # Path to your encryption key file
INPUT_FILE="$1"                  # Input encrypted file (first argument to the script)
OUTPUT_FILE="decrypted_file.dat" # Default output decrypted file name

# --- Check for input file ---
if [ -z "$INPUT_FILE" ]; then
  echo "Usage: $0 <encrypted_file>"
  echo "  <encrypted_file>  : Path to the downloaded encrypted file."
  echo "  Decrypted output will be saved as: $OUTPUT_FILE"
  exit 1
fi

if [ ! -f "$INPUT_FILE" ]; then
  echo "Error: Input file '$INPUT_FILE' not found."
  exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
  echo "Error: Key file '$KEY_FILE' not found. Make sure it's in the same directory as the script or update KEY_FILE variable."
  exit 1
fi

# --- Extract IV ---
echo "Extracting Initialization Vector (IV)..."
head -c 16 "$INPUT_FILE" >iv.bin
if [ ! -s "iv.bin" ]; then
  echo "Error: Failed to extract IV. Ensure the input file is a valid encrypted file."
  rm -f "iv.bin" # Clean up potential empty IV file
  exit 1
fi

# --- Extract Encrypted Data ---
echo "Extracting encrypted data..."
tail -c +17 "$INPUT_FILE" >encrypted_data.dat
if [ ! -s "encrypted_data.dat" ]; then
  echo "Error: Failed to extract encrypted data. Ensure the input file is a valid encrypted file."
  rm -f "iv.bin" "encrypted_data.dat" # Clean up temp files
  exit 1
fi

# --- Decrypt using OpenSSL ---
echo "Decrypting using OpenSSL AES-256-CBC..."
openssl enc -aes-256-cbc -d \
  -in encrypted_data.dat \
  -out "$OUTPUT_FILE" \
  -K $(xxd -p -c 32 "$KEY_FILE") \
  -iv $(xxd -p -c 16 iv.bin)

if [ $? -ne 0 ]; then
  echo "Error: OpenSSL decryption failed. Please check:"
  echo "  - Is OpenSSL installed and in your PATH?"
  echo "  - Is the encryption key '$KEY_FILE' correct?"
  echo "  - Is the input file '$INPUT_FILE' actually encrypted by the server?"
  rm -f "iv.bin" "encrypted_data.dat" # Clean up temp files
  exit 1
else
  echo "Decryption successful!"
  echo "Decrypted file saved as: $OUTPUT_FILE"
fi

# --- Clean up temporary files ---
echo "Cleaning up temporary files..."
rm -f "iv.bin" "encrypted_data.dat"

echo "Done."
exit 0
