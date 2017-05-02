package secp256k1

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"io"
	"strings"
	"testing"
)

const (
	TestSecretKey             string = `7ccca75d019dbae79ac4266501578684ee64eeb3c9212105f7a3bdc0ddb0f27e`
	TestPublicKeyCompressed   string = `03e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9`
	TestPublicKeyUncompressed string = `04e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e94c181c5fe89306493dd5677143a329065606740ee58b873e01642228a09ecf9d`

	TestCompactSig            string = `fe5fe404f3d8c21e1204a08c38ff3912d43c5a22541d2f1cdc4977cbcad240015a3b6e9040f62cacf016df4fef9412091592e4908e5e3a7bd2a42a4d1be01951`
	TestCompactSigKey         string = `fbb80e8a0f8af4fb52667e51963ac9860c192981f329debcc5d123a492a726af`
	TestCompactSigPublicKey   string = `03acc83ba10066e791d51e8a8eb90ec325feea7251cb8f979996848fff551d13`

	TestDerSig                string = `30440220132382ca59240c2e14ee7ff61d90fc63276325f4cbe8169fc53ade4a407c2fc802204d86fbe3bde6975dd5a91fdc95ad6544dcdf0dab206f02224ce7e2b151bd82ab01`
	TestDerMsg32              string = `9e5755ec2f328cc8635a55415d0e9a09c2b6f2c9b0343c945fbbfe08247a4cbe`
	TestDerPrivKey            string = `31a84594060e103f5a63eb742bd46cf5f5900d8406e2726dedfc61c7cf43ebad`
	TestDerPublicKey          string = `0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798`
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
func Test_EcdsaSignatureParseDer(t *testing.T) {
	ctx, err := ContextCreate(uint(ContextSign | ContextVerify))
	if err != nil {
		panic(err)
	}

	sigByte, err := hex.DecodeString(strings.TrimSuffix(TestDerSig, "01"))
	s, sig, err := EcdsaSignatureParseDer(ctx, sigByte)
	if err != nil {
		panic(err)
	}

	assert.IsType(t, EcdsaSignature{}, *sig)
	assert.Equal(t, 1, s)
	assert.NoError(t, err)

	s, out, err := EcdsaSignatureSerializeDer(ctx, sig)
	assert.Equal(t, 1, s)
	assert.NoError(t, err)
	assert.Equal(t, sigByte, out)

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