package mobileproxy

import "github.com/ProtonMail/gopenpgp/v3/crypto"

func Encrypt(pubkey string, message []byte) (string, error) {
	pgp := crypto.PGP()

	publicKey, err := crypto.NewKeyFromArmored(pubkey)
	if err != nil {
		return "", err
	}

	encHandle, err := pgp.Encryption().Recipient(publicKey).New()
	if err != nil {
		return "", err
	}

	pgpMessage, err := encHandle.Encrypt(message)
	if err != nil {
		return "", err
	}

	return pgpMessage.Armor()
}
