package encrypt

import (
	"github.com/stretchr/testify/assert"
	"testing"
)


func TestAes(t *testing.T) {

	key := []byte("1234567809876543")
	plainText := []byte("ha a ha, e a e")
	enc, err := AesCbcEncrypt(plainText, key)
	assert.Nil(t, err)
	t.Logf("enc:  %v", enc)

	pt, err := AesCbcDecrypt(enc, key)
	assert.Nil(t, err)
	assert.Equal(t, pt, plainText)

	enc, err = AesCtrEncrypt(plainText, key)
	assert.Nil(t, err)
	t.Logf("enc:  %v", enc)

	pt, err = AesCtrDecrypt(enc, key)
	assert.Nil(t, err)
	assert.Equal(t, pt, plainText)
}

