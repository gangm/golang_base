package encrypt

import (
	"bytes"
	"crypto/sha256"
	"crypto/rand"
	"encoding/hex"
	"encoding/pem"
	"crypto/x509"
	"log"
	"runtime"
	"crypto/ecdsa"
	"math/big"
)

/*
@Time : 2018/11/4 18:51 
@Author : wuman
@File : EccSign
@Software: GoLand
*/

func init(){
	log.SetFlags(log.Ldate|log.Lshortfile)
}

func EccSign(msg []byte,Key []byte)([]byte, error){
	block, _ := pem.Decode(Key)

	defer func(){
		if err:=recover();err!=nil{
			switch err.(type){
			case runtime.Error:
				log.Println("runtime err:",err,"Check that the key is correct")
			default:
				log.Println("error:",err)
			}
		}
	}()
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err!=nil{
		return nil, err
	}
	myhash := sha256.New()
	myhash.Write(msg)
	resultHash := myhash.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, privateKey, resultHash)
	if err!=nil{
		return nil, err
	}

	rText, err := r.MarshalText()
	if err!=nil{
		return nil, err
	}
	sText, err := s.MarshalText()
	if err!=nil{
		return nil, err
	}
	var b bytes.Buffer
	b.Write(rText)
	b.Write([]byte(`+`))
	b.Write(sText)
	return b.Bytes(), nil
}

func EccVerifySign(msg []byte,Key []byte, sign []byte) bool {
	block, _ := pem.Decode(Key)
	defer func(){
		if err:=recover();err!=nil{
			switch err.(type){
			case runtime.Error:
				log.Println("runtime err:",err,"Check that the key is correct")
			default:
				log.Println("error:",err)
			}
		}
	}()
	publicKeyInterface, _ := x509.ParsePKIXPublicKey(block.Bytes)
	publicKey:=publicKeyInterface.(*ecdsa.PublicKey)
	myhash := sha256.New()
	myhash.Write(msg)
	resultHash := myhash.Sum(nil)

	var r,s big.Int
	rs := bytes.Split(sign, []byte("+"))
	if len(rs) != 2 {
		log.Println("invalid sign param", hex.EncodeToString(sign))
		return false
	}

	r.UnmarshalText(rs[0])
	s.UnmarshalText(rs[1])

	result := ecdsa.Verify(publicKey, resultHash, &r, &s)
	return result
}