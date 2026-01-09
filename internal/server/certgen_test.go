package server

import (
	"crypto/tls"
	"os"
	"testing"
)

func TestGenerateSelfSignedCert(t *testing.T) {
	certFile := "test_cert.pem"
	keyFile := "test_key.pem"

	// Cleanup after test
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	// cleanup before test just in case
	os.Remove(certFile)
	os.Remove(keyFile)

	err := GenerateSelfSignedCert(certFile, keyFile)
	if err != nil {
		t.Fatalf("GenerateSelfSignedCert failed: %v", err)
	}

	// Verify files exist
	if !FileExists(certFile) {
		t.Errorf("Certificate file was not created")
	}
	if !FileExists(keyFile) {
		t.Errorf("Key file was not created")
	}

	// Verify we can load the pair
	_, err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("Failed to load generated key pair: %v", err)
	}
}

func TestFileExists(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "testfile")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	if !FileExists(tmpFile.Name()) {
		t.Error("FileExists returned false for existing file")
	}

	if FileExists("non_existent_file_12345") {
		t.Error("FileExists returned true for non-existing file")
	}
}
