package secp256k1

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
)

const (
	TestCompactSig   string = `fe5fe404f3d8c21e1204a08c38ff3912d43c5a22541d2f1cdc4977cbcad240015a3b6e9040f62cacf016df4fef9412091592e4908e5e3a7bd2a42a4d1be01951`
	TestDerMsg32     string = `9e5755ec2f328cc8635a55415d0e9a09c2b6f2c9b0343c945fbbfe08247a4cbe`
	TestDerPrivKey   string = `31a84594060e103f5a63eb742bd46cf5f5900d8406e2726dedfc61c7cf43ebad`
	TestDerPublicKey string = `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798`
)

func testingRand32() [32]byte {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return key
}
func testingRand(n int) []byte {
	key := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return key
}

func Test_ContextCreate1(t *testing.T) {

	params := uint(ContextSign | ContextVerify)
	ctx, err := ContextCreate(params)

	assert.NoError(t, err)
	assert.NotNil(t, ctx)
	assert.IsType(t, Context{}, *ctx)

	clone, err := ContextClone(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, ctx)
	assert.IsType(t, Context{}, *ctx)

	ContextDestroy(clone)

	res := ContextRandomize(ctx, testingRand32())
	assert.Equal(t, 1, res)
}

func Test_EcdsaSignatureParseCompact(t *testing.T) {
	ctx, err := ContextCreate(uint(ContextSign | ContextVerify))
	if err != nil {
		panic(err)
	}

	sigByte, err := hex.DecodeString(TestCompactSig)

	s, sig, err := EcdsaSignatureParseCompact(ctx, sigByte)
	if err != nil {
		panic(err)
	}

	assert.IsType(t, EcdsaSignature{}, *sig)
	assert.Equal(t, 1, s)
	assert.NoError(t, err)

	s, out, err := EcdsaSignatureSerializeCompact(ctx, sig)
	assert.Equal(t, 1, s)
	assert.NoError(t, err)
	assert.Equal(t, TestCompactSig, hex.EncodeToString(out))

}

func TestEcdsaVerify(t *testing.T) {
	ctx, err := ContextCreate(uint(ContextSign | ContextVerify))
	if err != nil {
		panic(err)
	}

	msg32, err := hex.DecodeString(TestDerMsg32)
	priv, err := hex.DecodeString(TestDerPrivKey)

	s, sig, err := EcdsaSign(ctx, msg32, priv)

	assert.Equal(t, 1, s)
	assert.NoError(t, err)
	assert.IsType(t, EcdsaSignature{}, *sig)

	s, pk, err := EcPubkeyCreate(ctx, priv)
	assert.Equal(t, 1, s)
	assert.NoError(t, err)
	assert.IsType(t, PublicKey{}, *pk)

	result := EcdsaVerify(ctx, sig, msg32, pk)
	assert.Equal(t, 1, result)
}
