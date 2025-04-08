package tpmcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const TPMDevice = "/dev/tpm0" // Path to the TPM device

// Encrypts a string using the TPM2 key at the given handle and returns the result as Base64.
func EncryptString(input string, keyHandle tpmutil.Handle) (string, error) {
	rwc, err := tpm2.OpenTPM(TPMDevice)
	if err != nil {
		return "", fmt.Errorf("failed to open TPM: %v", err)
	}
	defer rwc.Close()

	// Ensure the TPM2 key exists
	if err := ensureTPMKey(rwc, keyHandle); err != nil {
		return "", fmt.Errorf("failed to ensure TPM2 key: %v", err)
	}

	// Generate a random AES key
	aesKey := make([]byte, 32) // 256-bit AES key
	if _, err := rand.Read(aesKey); err != nil {
		return "", fmt.Errorf("failed to generate AES key: %v", err)
	}

	// Define the encryption scheme)
	scheme := &tpm2.AsymScheme{
		Alg:  tpm2.AlgRSAES,
		Hash: tpm2.AlgSHA256,
	}

	// Encrypt the AES key with the TPM2 RSA public key
	encryptedAESKey, err := tpm2.RSAEncrypt(rwc, keyHandle, aesKey, scheme, "")
	if err != nil {
		return "", fmt.Errorf("failed to encrypt AES key with TPM: %v", err)
	}

	// Encrypt the input string with the AES key
	encryptedData, err := encryptWithAES([]byte(input), aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt data with AES: %v", err)
	}

	// Combine the encrypted AES key and encrypted data
	result := append(encryptedAESKey, encryptedData...)

	return base64.StdEncoding.EncodeToString(result), nil
}

// Decrypts a Base64-encoded string using the TPM2 key at the given handle.
func DecryptString(encryptedBase64 string, keyHandle tpmutil.Handle) (string, error) {
	rwc, err := tpm2.OpenTPM(TPMDevice)
	if err != nil {
		return "", fmt.Errorf("failed to open TPM: %v", err)
	}
	defer rwc.Close()

	encryptedData, err := base64.StdEncoding.DecodeString(encryptedBase64)
	if err != nil {
		return "", fmt.Errorf("failed to decode Base64: %v", err)
	}

	// Split the encrypted AES key and encrypted data
	if len(encryptedData) < 256 {
		return "", errors.New("invalid encrypted data length")
	}
	encryptedAESKey := encryptedData[:256]
	ciphertext := encryptedData[256:]

	// Define the decryption scheme
	scheme := &tpm2.AsymScheme{
		Alg:  tpm2.AlgRSAES,
		Hash: tpm2.AlgSHA256,
	}

	// Decrypt the AES key with the TPM2 RSA private key
	aesKey, err := tpm2.RSADecrypt(rwc, keyHandle, "", encryptedAESKey, scheme, "")
	if err != nil {
		return "", fmt.Errorf("failed to decrypt AES key with TPM: %v", err)
	}

	// Decrypt the data with the AES key
	plaintext, err := decryptWithAES(ciphertext, aesKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data with AES: %v", err)
	}

	return string(plaintext), nil
}

// EnsureTPMKey ensures a TPM2 key exists at the given handle. If not, it creates and persists the key.
func ensureTPMKey(rwc io.ReadWriteCloser, keyHandle tpmutil.Handle) error {
	// Check if the key already exists
	_, _, _, err := tpm2.ReadPublic(rwc, keyHandle)
	if err == nil {
		// Key already exists
		fmt.Printf("TPM2 key already exists at handle 0x%X\n", keyHandle)
		return nil
	}

	// Create a new primary key (RSA key for encryption purposes)
	template := tpm2.Public{
		Type:    tpm2.AlgRSA,
		NameAlg: tpm2.AlgSHA256,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent | tpm2.FlagSensitiveDataOrigin |
			tpm2.FlagUserWithAuth | tpm2.FlagDecrypt,
		RSAParameters: &tpm2.RSAParams{
			KeyBits: 2048,
		},
	}

	// Create the primary key
	privateHandle, _, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", template)
	if err != nil {
		return fmt.Errorf("failed to create primary key: %v", err)
	}
	defer tpm2.FlushContext(rwc, privateHandle)

	// Persist the key
	err = tpm2.EvictControl(rwc, "", tpm2.HandleOwner, privateHandle, keyHandle)
	if err != nil {
		return fmt.Errorf("failed to persist key: %v", err)
	}

	fmt.Printf("TPM2 key created and persisted at handle 0x%X\n", keyHandle)
	return nil
}

// Encrypts data using AES-256-CBC with PKCS#7 padding.
func encryptWithAES(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %v", err)
	}

	// Generate a random IV
	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %v", err)
	}

	paddedData := pad(data, aes.BlockSize)

	// Encrypt the data
	ciphertext := make([]byte, len(paddedData))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	// Prepend the IV to the ciphertext
	return append(iv, ciphertext...), nil
}

// Decrypts data using AES-256-CBC.
func decryptWithAES(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(data) < aes.BlockSize {
		return nil, errors.New("ciphertext too short")
	}

	// Extract the IV from the beginning of the ciphertext
	iv := data[:aes.BlockSize]
	ciphertext := data[aes.BlockSize:]

	// Decrypt the data
	plaintext := make([]byte, len(ciphertext))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	return unpad(plaintext)
}

// Adds PKCS#7 padding to the data.
func pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

// Removes PKCS#7 padding from the data.
func unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("data is empty")
	}
	padding := int(data[len(data)-1])
	if padding > len(data) || padding > aes.BlockSize {
		return nil, errors.New("invalid padding")
	}
	return data[:len(data)-padding], nil
}
