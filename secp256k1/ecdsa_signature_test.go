package secp256k1

import (
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestSignatureParseDerFixtures(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	fixtures := GetEcdsaFixtures()

	for i := 0; i < len(fixtures); i++ {
		sigBytes := fixtures[i].GetSigBytes()
		r, sig, err := EcdsaSignatureParseDer(ctx, sigBytes)
		spOK(t, r, err)

		r, serialized, err := EcdsaSignatureSerializeDer(ctx, sig)
		spOK(t, r, err)

		assert.Equal(t, sigBytes, serialized)
	}
}

func TestSignatureParseCompactFixtures(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	fixtures := GetEcdsaFixtures()

	for i := 0; i < len(fixtures); i++ {
		sigBytes := fixtures[i].GetSigBytes()
		r, sig, err := EcdsaSignatureParseDer(ctx, sigBytes)
		spOK(t, r, err)

		r, serialized, err := EcdsaSignatureSerializeDer(ctx, sig)
		spOK(t, r, err)

		assert.Equal(t, sigBytes, serialized)
	}
}
