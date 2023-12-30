package rsa

import (
	"os"
	"testing"
)

const bits = 4096 // Change as required

func TestGenerateKeyPair(t *testing.T) {
	// Generate a pair of keys
	keyPair, err := GenerateKeyPair(bits)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	// Validate the length of the password
	if got := keyPair.N.BitLen(); got != bits {
		t.Errorf("expected key length %d, got %d", bits, got)
	}

	// Validate that the password is valid
	if err := keyPair.Validate(); err != nil {
		t.Errorf("key validation failed: %v", err)
	}
}

func TestSavePrivateKeyAndLoad(t *testing.T) {
	// Generate a pair of keys
	keyPair, err := GenerateKeyPair(bits)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	// Save the private key in a file
	privateKeyFileName := "private_key.pem"
	if err := SavePrivateKey(privateKeyFileName, keyPair); err != nil {
		t.Fatalf("failed to save private key: %v", err)
	}

	// Load the private key from the file
	loadedKeyPair, err := LoadPrivateKey(privateKeyFileName)
	if err != nil {
		t.Fatalf("failed to load private key: %v", err)
	}

	// Compare the loaded keys with the original ones
	if !ComparePrivateKeys(keyPair, loadedKeyPair) {
		t.Error("loaded private key does not match original key")
	}

	// Clean up: delete the file
	defer func() {
		if err := os.Remove(privateKeyFileName); err != nil {
			t.Logf("failed to clean up: %v", err)
		}
	}()
}

func TestSavePublicKeyAndLoad(t *testing.T) {
	// Generate a pair of keys
	keyPair, err := GenerateKeyPair(bits)
	if err != nil {
		t.Fatalf("failed to generate key pair: %v", err)
	}

	// Save the public key in a file
	publicKeyFileName := "public_key.pem"
	if err := SavePublicKey(publicKeyFileName, keyPair); err != nil {
		t.Fatalf("failed to save public key: %v", err)
	}

	// Load the public key from the file
	loadedPublicKey, err := LoadPublicKey(publicKeyFileName)
	if err != nil {
		t.Fatalf("failed to load public key: %v", err)
	}

	// Compare the loaded keys with the original ones
	if !ComparePublicKeys(&keyPair.PublicKey, loadedPublicKey) {
		t.Error("loaded public key does not match original key")
	}

	// Clean up: delete the file
	defer func() {
		if err := os.Remove(publicKeyFileName); err != nil {
			t.Logf("failed to clean up: %v", err)
		}
	}()
}
