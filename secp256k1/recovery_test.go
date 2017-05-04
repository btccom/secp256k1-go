package secp256k1

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"log"
	"testing"
)

func TestParseRecoverableCompactSignatureRequires64Bytes(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	bad := []byte(`a`)
	r, sig, err := EcdsaRecoverableSignatureParseCompact(ctx, bad, 0)
	assert.Error(t, err)
	assert.Equal(t, 0, r)
	assert.Nil(t, sig)
	assert.Equal(t, ErrorCompactSigSize, err.Error())
}

func TestParseRecoverableSignatureMustBeValid(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	bad, err := hex.DecodeString(`FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364142`)
	if err != nil {
		panic(err)
	}

	for recid := 0; recid < 4; recid++ {
		r, sig, err := EcdsaRecoverableSignatureParseCompact(ctx, bad, recid)
		assert.Error(t, err)
		assert.Equal(t, 0, r)
		assert.Nil(t, sig)
		assert.Equal(t, ErrorRecoverableSigParse, err.Error())
	}
}

func TestEcdsaSignRecoverableChecksPrivkeySize(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	msg32 := testingRand(32)
	priv := []byte(`a`)

	r, _, err := EcdsaSignRecoverable(ctx, msg32, priv)
	assert.Equal(t, 0, r)
	assert.Error(t, err)
	assert.Equal(t, ErrorPrivateKeySize, err.Error())
}
func TestEcdsaSignRecoverableChecksMsg32(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	priv := testingRand(32)
	msg32 := []byte(`a`)

	r, _, err := EcdsaSignRecoverable(ctx, msg32, priv)
	assert.Equal(t, 0, r)
	assert.Error(t, err)
	assert.Equal(t, ErrorMsg32Size, err.Error())
}

func TestEcdsaRecoverCanError(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	priv := testingRand(32)
	msg32 := testingRand(32)
	msg32_2 := []byte(`a`)

	_, sig, err := EcdsaSignRecoverable(ctx, msg32, priv)
	assert.NoError(t, err)

	r, _, err := EcdsaRecover(ctx, sig, msg32)
	assert.Equal(t, 1, r)
	assert.NoError(t, err)

	r, _, err = EcdsaRecover(ctx, sig, msg32_2)
	assert.Equal(t, 0, r)
	assert.Error(t, err)
	assert.Equal(t, ErrorMsg32Size, err.Error())
}

func TestSerializeRecoverableSignatureWorksIfNull(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	sig := newEcdsaRecoverableSignature()

	r, sig64, recid, err := EcdsaRecoverableSignatureSerializeCompact(ctx, sig)
	assert.NoError(t, err)
	assert.Equal(t, 1, r)
	assert.Equal(t, 0, recid)
	log.Println(sig64)

}
