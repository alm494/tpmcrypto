# tpmcrypto

Encrypt and decrypt string data using TPM 2.0 capabilities in Golang. This approach provides a highly secure solution for persisting sensitive data in databases.

## Key features  

+ Uses hardware TMP 2.0 security chip presented on most mainboards;
+ Encrypted data can only be decrypted on the same computer where it was encrypted;
+ The TPM is used for asymmetric decryption (RSA), while symmetric decryption (AES) is handled in software;
+ Combines the encrypted AES key and ciphertext, then encodes the result in Base64.

## Limitations

+ Root privileges required to access TPM chip, or add your user to the tss group (may depend on Linux distro)
+ Your hardware may not contain TPM 2.0 chip;

## Example

```
// Specify the TPM2 key handle (read docs about range)
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
         
     
