# tpmcrypto

Encrypt and decrypt string data using TPM 2.0 capabilities in Golang.

This approach leverages the hardware-based security features of TPM 2.0 to provide a highly secure solution for persisting sensitive data in databases.

## Key features  

+ Hardware-Based Security : Utilizes the TPM 2.0 security chip, which is available on most modern motherboards, to ensure robust protection of sensitive data.
+ Machine-Specific Encryption : Encrypted data can only be decrypted on the same machine where it was encrypted, ensuring data remains tied to the hardware.
+ RSA Key Pair Management : Generates and securely stores a new RSA 2048-bit key pair on the TPM chip with the handle 0x81000100. (Refer to TPM documentation for details on handle ranges.)
+ Hybrid Encryption Approach :
++ The TPM performs asymmetric encryption/decryption using RSA.
++ The TPM performs asymmetric encryption/decryption using RSA.
+ Base64 Encoding : Combines the encrypted AES key and ciphertext, then encodes the result in Base64 for easy storage and transmission.
  
## Limitations

+ Privileged Access Required : Root privileges are necessary to access the TPM chip. Alternatively, you can add your user to the tss group (this may vary depending on the Linux distribution).
+ Hardware Dependency : This solution requires a TPM 2.0 chip, which may not be present on all systems.
+ Concurrency Restrictions : Avoid multithreaded access to the TPM, as it may lead to resource contention or unexpected behavior.

## Example

```
// Specify the TPM2 key handle
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
         
     
