package encrypt

import (
	"github.com/stretchr/testify/assert"
	"testing"
)


func TestDes(t *testing.T) {

	key := []byte("12345678")
	plainText := []byte("ha a ha, e a e")
	enc, err := DesCbcEncrypt(plainText, key)
	assert.Nil(t, err)
	t.Logf("enc:  %v", enc)

	pt, err := DesCbcDecrypt(enc, key)
	assert.Nil(t, err)
	assert.Equal(t, pt, plainText)


	key = []byte("12345678goaescrysjfdjsie")
	plainText = []byte("ha a ha, e a e")
	enc, err = TripleDesEncrypt(plainText, key)
	assert.Nil(t, err)
	t.Logf("enc:  %v", enc)

	pt, err = TripleDesDecrypt(enc, key)
	assert.Nil(t, err)
	assert.Equal(t, pt, plainText)
}

