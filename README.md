[![en](https://img.shields.io/badge/lang-en-red.svg)](https://github.com/alm494/tpmcrypto/blob/main/README.md)
[![en](https://img.shields.io/badge/lang-ru-red.svg)](https://github.com/alm494/tpmcrypto/blob/main/README.ru.md)

# tpmcrypto

A simple library for encrypting and decrypting string data using TPM 2.0 in the Go programming language. It uses a poorly documented library from Google. I just put everything together and made it work.

This approach leverages the hardware-based security features of TPM 2.0 to provide a highly secure solution for persisting sensitive data in databases.

## Key features  

+ Hardware-based security : utilizes the TPM 2.0 security chip, which is available on most modern motherboards, to ensure robust protection of sensitive data.
+ Machine-specific encryption : encrypted data can only be decrypted on the same machine where it was encrypted, ensuring data remains tied to the hardware.
+ RSA key pair management : generates and securely stores a new RSA 2048-bit key pair on the TPM chip with the handle specified in the allowed range. (Refer to TPM documentation for details on handle ranges). TPM supports stronger algos, so RSA is used just for compatibility as an example.
+ Hybrid encryption approach : the TPM performs asymmetric encryption/decryption using RSA, and symmetric encryption/decryption (AES) is handled in software for efficiency.
+ Base64 encoding : combines the encrypted AES key and ciphertext, then encodes the result in Base64 for easy storage and transmission.
  
## Limitations

+ You should be familiar with the limitations based on the local legislation of your country regarding the legality of using strong cryptography
+ Privileged access required : root privileges are necessary to access the TPM chip. Alternatively, you can add your user to the tss group (this may vary depending on the Linux distribution).
+ Hardware dependency : this solution requires a TPM 2.0 chip, which may not be present on all systems.
+ Concurrency restrictions : avoid multithreaded access to the TPM, as it may lead to resource contention or unexpected behavior.

## Example

```Go
// Specify the TPM2 key handle. Lower values 0x81000000, 0x81000001 etc may be
// in use already by your system
keyHandle := tpmutil.Handle(0x81000100)

// Encrypt a string
plaintext := "This is a secret password"
encrypted, err := tpmcrypto.EncryptString(plaintext, keyHandle)
if err != nil {
    log.Fatalf("Encryption failed: %v", err)
}
fmt.Printf("Encrypted String:\n%s\n", encrypted)

// Decrypt the string
decrypted, err := tpmcrypto.DecryptString(encrypted, keyHandle)
if err != nil {
    log.Fatalf("Decryption failed: %v", err)
}
fmt.Printf("Decrypted String:\n%s\n", decrypted)
```
         
     
