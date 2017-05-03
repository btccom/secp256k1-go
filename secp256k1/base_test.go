package secp256k1

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	EcdsaTestVectors = "sign_vectors.yaml"
)

func spOK(t *testing.T, result int, err error) {
	assert.NoError(t, err)
	assert.Equal(t, 1, result)
}