package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"fmt"
)

type Algorithm interface {
	CheckKeyAlgorithm(crypto.PublicKey) bool
	CheckHashAlgorithm(crypto.Hash) bool
}

type EcdsaSha256Algorithm struct{}

func (EcdsaSha256Algorithm) CheckKeyAlgorithm(key crypto.PublicKey) bool {
	_, ok := key.(*ecdsa.PublicKey)
	return ok
}

func (EcdsaSha256Algorithm) CheckHashAlgorithm(hash crypto.Hash) bool {
	return hash == crypto.SHA256
}

type Ed25519Algorithm struct{}

func (Ed25519Algorithm) CheckKeyAlgorithm(key crypto.PublicKey) bool {
	_, ok := key.(ed25519.PublicKey)
	return ok
}

func (Ed25519Algorithm) CheckHashAlgorithm(hash crypto.Hash) bool {
	return hash == crypto.Hash(0)
}

type AlgorithmRegistry struct {
	permittedAlgorithms []Algorithm
}

func NewAlgorithmRegistry(algorithmConfig []string) (*AlgorithmRegistry, error) {
	var permittedAlgorithms []Algorithm
	for _, algorithm := range algorithmConfig {
		switch algorithm {
		case "ecdsa-sha2-256-nistp256":
			permittedAlgorithms = append(permittedAlgorithms, EcdsaSha256Algorithm{})
		case "ed25519":
			permittedAlgorithms = append(permittedAlgorithms, Ed25519Algorithm{})
		default:
			return nil, fmt.Errorf("unknown algorithm: %s", algorithm)
		}
	}
	return &AlgorithmRegistry{permittedAlgorithms: permittedAlgorithms}, nil
}

func (registry AlgorithmRegistry) CheckAlgorithm(key crypto.PublicKey, hash crypto.Hash) error {
	for _, algorithm := range registry.permittedAlgorithms {
		if algorithm.CheckKeyAlgorithm(key) && algorithm.CheckHashAlgorithm(hash) {
			return nil
		}
	}
	return fmt.Errorf("signing algorithm not permitted: %T, %s", key, hash)
}
