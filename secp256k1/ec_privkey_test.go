package secp256k1

import (
	"gopkg.in/yaml.v2"
	"encoding/hex"
	"testing"
	"github.com/stretchr/testify/assert"
)

type PrivkeyTweakAddTestCase struct {
	PrivateKey string `yaml:"privkey"`
	Tweak string `yaml:"tweak"`
	Tweaked string `yaml:"tweaked"`
}

func (t *PrivkeyTweakAddTestCase) GetPrivateKey() []byte {
	public, err := hex.DecodeString(t.PrivateKey)
	if err != nil {
		panic("Invalid private key");
	}
	return public
}
func (t *PrivkeyTweakAddTestCase) GetTweak() []byte {
	tweak, err := hex.DecodeString(t.Tweak)
	if err != nil {
		panic(err)
	}
	return tweak
}
func (t *PrivkeyTweakAddTestCase) GetTweaked() []byte {
	tweaked, err := hex.DecodeString(t.Tweaked)
	if err != nil {
		panic(err)
	}
	return tweaked
}

type PrivkeyTweakAddFixtures []PrivkeyTweakAddTestCase

func GetPrivkeyTweakAddFixtures() PrivkeyTweakAddFixtures {
	source := readFile(PrivkeyTweakAddTestVectors)
	testCase := PrivkeyTweakAddFixtures{}
	err := yaml.Unmarshal(source, &testCase)
	if err != nil {
		panic(err)
	}
	return testCase
}

func TestPrivkeyTweakAddFixtures(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	fixtures := GetPrivkeyTweakAddFixtures()

	for i := 0; i < 1; i++ {
		fixture := fixtures[i]
		priv := fixture.GetPrivateKey()
		tweak := fixture.GetTweak();

		r, err := EcPrivkeyTweakAdd(ctx, priv, tweak)
		spOK(t, r, err)

		assert.Equal(t, fixture.GetTweaked(), priv)
	}
}

type PrivkeyTweakMulTestCase struct {
	PrivateKey string `yaml:"privkey"`
	Tweak string `yaml:"tweak"`
	Tweaked string `yaml:"tweaked"`
}

func (t *PrivkeyTweakMulTestCase) GetPrivateKey() []byte {
	public, err := hex.DecodeString(t.PrivateKey)
	if err != nil {
		panic("Invalid private key");
	}
	return public
}
func (t *PrivkeyTweakMulTestCase) GetTweak() []byte {
	tweak, err := hex.DecodeString(t.Tweak)
	if err != nil {
		panic(err)
	}
	return tweak
}
func (t *PrivkeyTweakMulTestCase) GetTweaked() []byte {
	tweaked, err := hex.DecodeString(t.Tweaked)
	if err != nil {
		panic(err)
	}
	return tweaked
}

type PrivkeyTweakMulFixtures []PrivkeyTweakMulTestCase

func GetPrivkeyTweakMulFixtures() PrivkeyTweakMulFixtures {
	source := readFile(PrivkeyTweakMulTestVectors)
	testCase := PrivkeyTweakMulFixtures{}
	err := yaml.Unmarshal(source, &testCase)
	if err != nil {
		panic(err)
	}
	return testCase
}

func TestPrivkeyTweakMulFixtures(t *testing.T) {
	ctx, err := ContextCreate(ContextSign | ContextVerify)
	if err != nil {
		panic(err)
	}

	fixtures := GetPrivkeyTweakMulFixtures()

	for i := 0; i < 1; i++ {
		fixture := fixtures[i]
		priv := fixture.GetPrivateKey()
		tweak := fixture.GetTweak();

		r, err := EcPrivkeyTweakMul(ctx, priv, tweak)
		spOK(t, r, err)

		assert.Equal(t, fixture.GetTweaked(), priv)
	}
}
