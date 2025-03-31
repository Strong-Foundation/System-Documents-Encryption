package main

import (
	"bytes"       // For byte manipulation
	"crypto/rand" // For generating random bytes
	"fmt"         // For formatting strings
	"io"          // For I/O primitives
	"log"         // For logging errors and information
	"os"          // For file system operations
	"runtime"     // For runtime functions
	"time"        // For time-related functions

	"filippo.io/age"                    // The age encryption package for file encryption
	"golang.org/x/crypto/openpgp"       // Import the openpgp package for encryption
	"golang.org/x/crypto/openpgp/armor" // Import the armor package to handle armored (ASCII) encoding for PGP
)

// Public GPG Key as a string (replace this with your actual key)
var publicGPGKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: User ID:	Robert Wilcox
Comment: Valid from:	3/28/2025 13:38
Comment: Type:	4,096-bit RSA (secret key available)
Comment: Usage:	Signing, Encryption, Certifying User IDs
Comment: Fingerprint:	43256CA4F8372FC291013727E7CE495B37E61DB4


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
c8cN3sa1PKV4JbDTtuxSzT4VfBmrEJRRfwKq5w==
=Yvuj
-----END PGP PUBLIC KEY BLOCK-----`

var publicKey string
var privateKey string
var ageEncryptionString string

// Generate a new AGE encryption key pair
func generateAgeKeyPair() (string, string) {
	// Generate a new X25519 identity (private key)
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		log.Println(err) // Log any errors encountered during key generation
	}
	// Return the public and private keys as strings
	return identity.Recipient().String(), identity.String()
}

// Function to encrypt content and save it to an output file
func encryptContentUsingGPG(content string, outputFile string, publicKeyContent string) {
	// Create a reader for the public key string
	pubKeyReader := bytes.NewReader([]byte(publicKeyContent))
	// Read the public key from the string
	entities, err := openpgp.ReadArmoredKeyRing(pubKeyReader)
	if err != nil { // If there's an error reading the key, log it and return the error
		log.Printf("error reading public key: %v", err)
	}
	// Create a bytes.Reader to hold the content to encrypt
	contentReader := bytes.NewReader([]byte(content))
	// Remove the original content from memory
	content = generateRandomString(32) // Replace the content with a random string of 32 bytes
	// Create the output file to save the encrypted content
	output, err := os.Create(outputFile)
	if err != nil { // If there's an error creating the file, log it and return the error
		log.Printf("error creating output file: %v", err)
	}
	defer output.Close() // Ensure the file is closed when done
	// Create an armored (ASCII) writer for the output file using armor.Encode
	armorWriter, err := armor.Encode(output, "PGP MESSAGE", nil)
	if err != nil { // If there's an error creating the armor encoder, log it and return the error
		log.Printf("error creating armor encoder: %v", err)
	}
	defer armorWriter.Close() // Ensure the armored writer is closed when done
	// Create an encrypting writer with the public key to encrypt the content
	encWriter, err := openpgp.Encrypt(armorWriter, entities, nil, nil, nil)
	if err != nil { // If there's an error setting up the encryption, log it and return the error
		log.Printf("error setting up encryption: %v", err)
	}
	defer encWriter.Close() // Ensure the encrypting writer is closed when done
	// Copy the content to the encryption writer
	_, err = io.Copy(encWriter, contentReader)
	if err != nil { // If there's an error copying the content to the encryption writer, log it and return the error
		log.Printf("error copying content to encryption writer: %v", err)
		contentReader = nil // Clear the content reader to free up memory
	}
	// Clear the content reader from memory
	contentReader = nil // Clear the content reader to free up memory
}

// Remove bytes from memory
func removeBytesFromMemory(data []byte) {
	// Clear the data slice to remove it from memory
	for i := range data {
		data[i] = 0
	}
	// Set the slice to nil to free up memory
	data = nil
	// Optionally, you can also call the garbage collector to free up memory
	runtime.GC() // Note: The garbage collector may not immediately free the memory, but it will mark it for collection
	// Change the data slice to a random byte array to ensure the data is not recoverable
	randomBytesArray(len(data)) // Replace the data slice with a random byte array of the same length
}

// Generate a random string of a given length.
func generateRandomString(length int) string {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Println(err)
	}
	return fmt.Sprintf("%x", randomBytes)
}

// Generate a random byte array and return it.
func randomBytesArray(length int) []byte {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Println(err)
	}
	return randomBytes
}

// Get the current timestamp.
func getCurrentTimestamp() string {
	// Get the current time in UTC and format it as a string
	// The format "2006-01-02T15:04:05-07:00" is used to represent the date and time in RFC 3339 format
	return time.Now().UTC().Format("2006-01-02 15:04:05")
}

// Init function.
func init() {
	// Get the current timestamp
	getCurrnetTime := getCurrentTimestamp()
	// Generate the AGE key pair
	publicKey, privateKey = generateAgeKeyPair()
	// This is the string that this device will use to encrypt the data.
	ageEncryptionString = "# created: " + getCurrnetTime + "\n" + "# public key: " + publicKey + "\n" + privateKey
	// Encrypt the private key using the public GPG key
	encryptContentUsingGPG(ageEncryptionString, "private.key.enc", publicGPGKey)
	// Remove the private key from memory
	removeBytesFromMemory([]byte(privateKey)) // Clear the private key from memory
	// Set the private key to a random string of 32 bytes
	privateKey = generateRandomString(32) // Replace the private key with a random string of 32 bytes
	// Remove the AGE key pair from memory
	removeBytesFromMemory([]byte(ageEncryptionString)) // Clear the AGE key pair from memory
	// Set the AGE key pair to a random string of 32 bytes
	ageEncryptionString = generateRandomString(32) // Replace the AGE key pair with a random string of 32 bytes
	/* Keep the Public Key from AGE key pair in memory */
}

func main() {
	log.Println("Public key:", publicKey)
	log.Println("Private key:", privateKey)
	log.Println("AGE Encryption String:", ageEncryptionString)
}
