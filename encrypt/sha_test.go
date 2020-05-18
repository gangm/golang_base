package encrypt

import (
	"encoding/hex"
	"testing"
)


func TestSha(t *testing.T) {

	plainText := []byte("ha a ha, e a e")
	res := Sha256(plainText)
	t.Logf(hex.EncodeToString(res))

	res = Sha512(plainText)
	t.Logf(hex.EncodeToString(res))
}

