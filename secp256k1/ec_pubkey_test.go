package secp256k1

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
	"testing"
)

type PubkeyCreateTestCase struct {
	PrivateKey      string `yaml:"seckey"`
	CompressedKey   string `yaml:"compressed"`
	UncompressedKey string `yaml:"pubkey"`
}

func (t *PubkeyCreateTestCase) GetPrivateKey() []byte {
	private, err := hex.DecodeString(t.PrivateKey)
	if err != nil {
		panic("Invalid private key")
	}
	return private
}
func (t *PubkeyCreateTestCase) GetCompressed() []byte {
	compressed, err := hex.DecodeString(t.CompressedKey)
	if err != nil {
		panic(err)
	}
	return compressed
}
func (t *PubkeyCreateTestCase) GetUncompressed() []byte {
	uncompressed, err := hex.DecodeString(t.UncompressedKey)
	if err != nil {
		panic(err)
	}
	return uncompressed
}

type PubkeyCreateFixtures []PubkeyCreateTestCase

func GetPubkeyCreateFixtures() PubkeyCreateFixtures {
	source := readFile(PubkeyCreateTestVectors)
	testCase := PubkeyCreateFixtures{}
	err := yaml.Unmarshal(source, &testCase)
	if err != nil {
		panic(err)
	}
	return testCase
}

func TestPubkeyCreateFixtures(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	fixtures := GetPubkeyCreateFixtures()

	for i := 0; i < len(fixtures); i++ {
		testCase := fixtures[i]
		priv := testCase.GetPrivateKey()

		r, publicKey, err := EcPubkeyCreate(ctx, priv)
		spOK(t, r, err)

		r, serializedComp, err := EcPubkeySerialize(ctx, publicKey, EcCompressed)
		spOK(t, r, err)
		assert.Equal(t, testCase.GetCompressed(), serializedComp)

		r, serializedUncomp, err := EcPubkeySerialize(ctx, publicKey, EcUncompressed)
		spOK(t, r, err)
		assert.Equal(t, testCase.GetUncompressed(), serializedUncomp)
	}
}

func TestPubkeyParseFixtures(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	fixtures := GetPubkeyCreateFixtures()

	for i := 0; i < len(fixtures); i++ {
		assertCanReadAndWritePublicKey(t, ctx, fixtures[i].GetUncompressed(), EcUncompressed)
		assertCanReadAndWritePublicKey(t, ctx, fixtures[i].GetCompressed(), EcCompressed)
	}
}

type PubkeyTweakAddTestCase struct {
	PublicKey string `yaml:"publicKey"`
	Tweak     string `yaml:"tweak"`
	Tweaked   string `yaml:"tweaked"`
}

func (t *PubkeyTweakAddTestCase) GetPublicKeyBytes() []byte {
	public, err := hex.DecodeString(t.PublicKey)
	if err != nil {
		panic("Invalid private key")
	}
	return public
}
func (t *PubkeyTweakAddTestCase) GetPublicKey(ctx *Context) *PublicKey {
	bytes := t.GetPublicKeyBytes()
	_, pubkey, err := EcPubkeyParse(ctx, bytes)
	if err != nil {
		panic(err)
	}
	return pubkey
}
func (t *PubkeyTweakAddTestCase) GetTweak() []byte {
	tweak, err := hex.DecodeString(t.Tweak)
	if err != nil {
		panic(err)
	}
	return tweak
}
func (t *PubkeyTweakAddTestCase) GetTweaked() []byte {
	tweaked, err := hex.DecodeString(t.Tweaked)
	if err != nil {
		panic(err)
	}
	return tweaked
}

type PubkeyTweakAddFixtures []PubkeyTweakAddTestCase

func GetPubkeyTweakAddFixtures() PubkeyTweakAddFixtures {
	source := readFile(PubkeyTweakAddTestVectors)
	testCase := PubkeyTweakAddFixtures{}
	err := yaml.Unmarshal(source, &testCase)
	if err != nil {
		panic(err)
	}
	return testCase
}

func TestPubkeyTweakAddFixtures(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	fixtures := GetPubkeyTweakAddFixtures()

	for i := 0; i < 1; i++ {
		fixture := fixtures[i]
		pubkey := fixture.GetPublicKey(ctx)
		tweak := fixture.GetTweak()

		r, err := EcPubkeyTweakAdd(ctx, pubkey, tweak)
		spOK(t, r, err)

		r, serialized, err := EcPubkeySerialize(ctx, pubkey, EcUncompressed)
		spOK(t, r, err)

		assert.Equal(t, fixture.GetTweaked(), serialized)
	}
}

type PubkeyTweakMulTestCase struct {
	PublicKey string `yaml:"publicKey"`
	Tweak     string `yaml:"tweak"`
	Tweaked   string `yaml:"tweaked"`
}

func (t *PubkeyTweakMulTestCase) GetPublicKeyBytes() []byte {
	public, err := hex.DecodeString(t.PublicKey)
	if err != nil {
		panic("Invalid private key")
	}
	return public
}
func (t *PubkeyTweakMulTestCase) GetPublicKey(ctx *Context) *PublicKey {
	bytes := t.GetPublicKeyBytes()
	_, pubkey, err := EcPubkeyParse(ctx, bytes)
	if err != nil {
		panic(err)
	}
	return pubkey
}
func (t *PubkeyTweakMulTestCase) GetTweak() []byte {
	tweak, err := hex.DecodeString(t.Tweak)
	if err != nil {
		panic(err)
	}
	return tweak
}
func (t *PubkeyTweakMulTestCase) GetTweaked() []byte {
	tweaked, err := hex.DecodeString(t.Tweaked)
	if err != nil {
		panic(err)
	}
	return tweaked
}

type PubkeyTweakMulFixtures []PubkeyTweakMulTestCase

func GetPubkeyTweakMulFixtures() PubkeyTweakMulFixtures {
	source := readFile(PubkeyTweakMulTestVectors)
	testCase := PubkeyTweakMulFixtures{}
	err := yaml.Unmarshal(source, &testCase)
	if err != nil {
		panic(err)
	}
	return testCase
}

func TestPubkeyTweakMulFixtures(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	fixtures := GetPubkeyTweakMulFixtures()

	for i := 0; i < 1; i++ {
		fixture := fixtures[i]
		pubkey := fixture.GetPublicKey(ctx)
		tweak := fixture.GetTweak()

		r, err := EcPubkeyTweakMul(ctx, pubkey, tweak)
		spOK(t, r, err)

		r, serialized, err := EcPubkeySerialize(ctx, pubkey, EcUncompressed)
		spOK(t, r, err)

		assert.Equal(t, fixture.GetTweaked(), serialized)
	}
}

func TestPubkeyMustBeValid(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	numTests := 1

	badKey, err := hex.DecodeString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	if err != nil {
		panic(err)
	}

	tests := make([][]byte, numTests)
	tests[0] = badKey

	for i := 0; i < numTests; i++ {
		r, pubkey, err := EcPubkeyCreate(ctx, tests[i])
		assert.Error(t, err)
		assert.Equal(t, 0, r)
		assert.Nil(t, pubkey)
		assert.Equal(t, ErrorPublicKeyCreate, err.Error())
	}

}


func TestPubkeyCreateChecksSize(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	badKey, _ := hex.DecodeString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

	r, pubkey, err := EcPubkeyCreate(ctx, badKey)
	assert.Error(t, err)
	assert.Equal(t, 0, r)
	assert.Nil(t, pubkey)
	assert.Equal(t, ErrorPrivateKeySize, err.Error())
}



func TestPubkeyTweakAddChecksTweakSize(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	pubkey, _ := hex.DecodeString("03e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9")
	_, pk, err := EcPubkeyParse(ctx, pubkey)
	if err != nil {
		panic(err)
	}

	badTweak, _ := hex.DecodeString("AAAA")

	r, err := EcPubkeyTweakAdd(ctx, pk, badTweak)
	assert.Error(t, err)
	assert.Equal(t, 0, r)
	assert.Equal(t, ErrorTweakSize, err.Error())
}

func TestPubkeyTweakMulChecksTweakSize(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	pubkey, _ := hex.DecodeString("03e9a06e539d6bf5cf1ca5c41b59121fa3df07a338322405a312c67b6349a707e9")
	_, pk, err := EcPubkeyParse(ctx, pubkey)
	if err != nil {
		panic(err)
	}

	badTweak, _ := hex.DecodeString("AAAA")

	r, err := EcPubkeyTweakMul(ctx, pk, badTweak)
	assert.Error(t, err)
	assert.Equal(t, 0, r)
	assert.Equal(t, ErrorTweakSize, err.Error())
}
