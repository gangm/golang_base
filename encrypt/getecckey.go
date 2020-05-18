package encrypt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
)

/*
@Time : 2018/11/4 16:22 
@Author : wuman
@File : GetECCKey
@Software: GoLand
*/
func init(){
	log.SetFlags(log.Ldate|log.Lshortfile)
}

func GetEccKey()(privKey, pubKey []byte, err error){
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err!=nil{
		return nil, nil, err
	}

	x509PrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	if err!=nil{
		return nil, nil, err
	}

	block := pem.Block{
		Type:  "ECC PRIVATE KEY",
		Bytes: x509PrivateKey,
	}
	privKey = pem.EncodeToMemory(&block)

	x509PublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err!=nil {
		return nil, nil, err
	}
	publicBlock := pem.Block{
		Type:  "ECC PUBLIC KEY",
		Bytes: x509PublicKey,
	}

	pubKey = pem.EncodeToMemory(&publicBlock)
	return privKey, pubKey,nil
}

func GetEccKeyByte()(privKey, pubKey []byte, err error){
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err!=nil{
		return nil, nil, err
	}

	x509PrivateKey, err := x509.MarshalECPrivateKey(privateKey)
	if err!=nil{
		return nil, nil, err
	}

	x509PublicKey, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err!=nil {
		return nil, nil, err
	}
	return x509PrivateKey, x509PublicKey,nil
}



