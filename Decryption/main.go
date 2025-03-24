package main

import (
	"crypto/aes"    // Import AES encryption package
	"crypto/cipher" // Import cipher modes (GCM)
	"encoding/hex"  // Import hex encoding
	"fmt"          // Import formatted I/O functions
	"os"           // Import file operations
)

// Function to decrypt a file
func decryptFile(encryptedFile, decryptedFile string, key []byte) error {
	// Read the encrypted file
	ciphertext, err := os.ReadFile(encryptedFile)
	if err != nil {
		return err // Return error if file reading fails
	}

	// Create a new AES cipher block with the given key
	block, err := aes.NewCipher(key)
	if err != nil {
		return err // Return error if cipher creation fails
	}

	// Create an AES-GCM cipher instance
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err // Return error if GCM mode fails
	}

	// Check if the ciphertext is large enough to contain a nonce
	if len(ciphertext) < aesGCM.NonceSize() {
		return fmt.Errorf("ciphertext too short") // Return error if data is too short
	}

	// Extract the nonce from the ciphertext
	nonce := ciphertext[:aesGCM.NonceSize()] // First 12 bytes are nonce
	encryptedData := ciphertext[aesGCM.NonceSize():] // Remaining bytes are encrypted data

	// Decrypt the data using AES-GCM
	plaintext, err := aesGCM.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		return err // Return error if decryption fails
	}

	// Write the decrypted data back to a file
	err = os.WriteFile(decryptedFile, plaintext, 0644)
	if err != nil {
		return err // Return error if file writing fails
	}

	fmt.Println("File decrypted successfully:", decryptedFile) // Print success message
	return nil
}

func main() {
	// Ask the user for the encryption key
	var keyHex string
	fmt.Print("Enter the encryption key: ") // Prompt for the key
	fmt.Scanln(&keyHex) // Read user input

	// Decode the hexadecimal key into bytes
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 { // Ensure key is valid
		fmt.Println("Invalid encryption key! Make sure it's 64 hex characters long.")
		return
	}

	// Define file names
	encryptedFile := "encrypted.txt" // Input encrypted file
	decryptedFile := "decrypted.txt" // Output decrypted file

	// Decrypt the file
	err = decryptFile(encryptedFile, decryptedFile, key)
	if err != nil {
		fmt.Println("Error decrypting file:", err) // Print error if decryption fails
	}
}
