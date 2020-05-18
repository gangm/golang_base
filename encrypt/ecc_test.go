package encrypt

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestEcc(t *testing.T) {


	privKey, pubKey, _ := GetEccKey()
	t.Logf("priv %v, pub %v", string(privKey), string(pubKey))

	priv, pub, _ := GetEccKeyByte()
	t.Logf("priv %v, \npub %v", string(hex.EncodeToString(priv)), string(hex.EncodeToString(pub)))

	// test encrypt and decrypt
	plainTxt := []byte("to test plain text")
	enc, _ := EccEncrypt(plainTxt, pubKey)
	t.Logf(hex.EncodeToString(enc))

	dec, _ := EccDecrypt(enc, privKey)
	t.Logf(string(dec))

	sign, _ := EccSign(plainTxt, privKey)
	t.Logf(hex.EncodeToString(sign))
	pass := EccVerifySign(plainTxt, pubKey, sign)
	t.Logf("%v", pass)
	assert.True(t, pass)



}
