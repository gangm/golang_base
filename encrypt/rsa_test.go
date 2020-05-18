package encrypt

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRsa(t *testing.T) {

	privKey, pubKey, _ := GetRsaKey()
	t.Logf("priv %v, pub %v", string(privKey), string(pubKey))

	priv, pub, _ := GetRsaKeyByte()
	t.Logf("priv %v, \npub %v", string(hex.EncodeToString(priv)), string(hex.EncodeToString(pub)))

	// test encrypt and decrypt
	plainTxt := []byte("to test plain text")
	enc, _ := RsaEncrypt(plainTxt, pubKey)
	t.Logf(hex.EncodeToString(enc))

	dec, _ := RsaDecrypt(enc, privKey)
	t.Logf(string(dec))

	sign, _ := RsaSign(plainTxt, privKey)
	t.Logf(hex.EncodeToString(sign))
	pass := RsaVerifySign(plainTxt, sign, pubKey)
	t.Logf("%v", pass)
	assert.True(t, pass)

}


