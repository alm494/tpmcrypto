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
