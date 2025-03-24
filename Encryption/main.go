package main

import (
	"crypto/aes"        // Import AES encryption package
	"crypto/cipher"     // Import cipher modes (GCM)
	"crypto/rand"       // Import random number generator
	"encoding/hex"      // Import hex encoding
	"fmt"              // Import formatted I/O functions
	"io"               // Import I/O functions
	"os"               // Import file operations
)

// Function to generate a random 32-byte AES key
func generateKey() ([]byte, error) {
	key := make([]byte, 32) // Create a 32-byte slice for AES-256 key
	_, err := rand.Read(key) // Fill the key with random bytes
	if err != nil {
		return nil, err // Return error if key generation fails
	}
	return key, nil // Return the generated key
}

// Function to encrypt a file
func encryptFile(inputFile, outputFile string, key []byte) error {
	// Read the content of the input file
	plaintext, err := os.ReadFile(inputFile)
	if err != nil {
		return err // Return error if reading fails
	}

	// Create a new AES cipher block using the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return err // Return error if cipher creation fails
	}

	// Generate a random nonce (12 bytes for AES-GCM)
	nonce := make([]byte, 12) // Nonce must be unique for each encryption
	_, err = rand.Read(nonce) // Fill nonce with random bytes
	if err != nil {
		return err // Return error if nonce generation fails
	}

	// Create a GCM cipher mode instance
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err // Return error if GCM mode fails
	}

	// Encrypt the data using AES-GCM
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)

	// Write the encrypted data (nonce + ciphertext) to the output file
	err = os.WriteFile(outputFile, ciphertext, 0644)
	if err != nil {
		return err // Return error if file writing fails
	}

	fmt.Println("File encrypted successfully:", outputFile) // Print success message
	return nil
}

func main() {
	// Generate an encryption key
	key, err := generateKey()
	if err != nil {
		fmt.Println("Error generating key:", err)
		return
	}

	// Print the encryption key (must be saved securely to decrypt later)
	keyHex := hex.EncodeToString(key) // Convert key to hexadecimal
	fmt.Println("Encryption Key (SAVE THIS!):", keyHex) // Display the key

	// Define file names
	inputFile := "plaintext.txt"     // Original plaintext file
	encryptedFile := "encrypted.txt" // Output encrypted file

	// Encrypt the file
	err = encryptFile(inputFile, encryptedFile, key)
	if err != nil {
		fmt.Println("Error encrypting file:", err) // Print error if encryption fails
	}
}
