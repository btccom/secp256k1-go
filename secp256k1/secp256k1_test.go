package secp256k1

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
)

const (
	TestSecretKey             string = `7ccca75d019dbae79ac4266501578684ee64eeb3c9212105f7a3bdc0ddb0f27e`
	TestPublicKeyCompressed   string = `03e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9`
	TestPublicKeyUncompressed string = `04e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e94c181c5fe89306493dd5677143a329065606740ee58b873e01642228a09ecf9d`
)

func testingRand32() [32]byte {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return key
}

func Test_ContextCreate(t *testing.T) {

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

func Test_EcPubkeyParse(t *testing.T) {
	ctx, err := ContextCreate(uint(ContextSign | ContextVerify))
	if err != nil {
		panic(err)
	}

	publicKey, err := hex.DecodeString(TestPublicKeyCompressed)
	s, pk, err := EcPubkeyParse(ctx, publicKey)
	if err != nil {
		panic(err)
	}

	assert.IsType(t, PublicKey{}, *pk)
	assert.Equal(t, 1, s)
	assert.NoError(t, err)

	s, out, err := EcPubkeySerialize(ctx, pk, EcCompressed)
	assert.Equal(t, 1, s)
	assert.NoError(t, err)
	assert.Equal(t, TestPublicKeyCompressed, hex.EncodeToString(out))

}
