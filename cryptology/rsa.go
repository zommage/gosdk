// 密码学, 各种加解密算法，签名算法
package cryptology

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
)

var (
	rsaSertKey []byte // rsa 私钥文件
	rsaPubKey  []byte // rsa

	pubKey2 = []byte(`
		-----BEGIN PUBLIC KEY-----
		MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCk7D8VRbOOrM6ftQqpsxQBryfT
		cfgiBvxf/Y/K5PM5pkmstvztWzBP7OYfWlFN1Fv2JIxsCULcZK1TvUswTqxjMlJv
		gPpLJS9rUH9n/kQWCQkL/Bk8nThY3P+wEdTX4/1mCYJRMlSWP9Nft09C2/3CUjO5
		rw32bP8HxTG4jlhsLQIDAQAB
		-----END PUBLIC KEY-----`)

	privateKey2 = []byte(`
		-----BEGIN PRIVATE KEY-----
		MIICdgIBADANBgkqhkiG9w0BAQEFAASCAmAwggJcAgEAAoGBAKTsPxVFs46szp+1
		CqmzFAGvJ9Nx+CIG/F/9j8rk8zmmSay2/O1bME/s5h9aUU3UW/YkjGwJQtxkrVO9
		SzBOrGMyUm+A+kslL2tQf2f+RBYJCQv8GTydOFjc/7AR1Nfj/WYJglEyVJY/01+3
		T0Lb/cJSM7mvDfZs/wfFMbiOWGwtAgMBAAECgYBRO2v29lXyuHstfua5n1MDYVqk
		c0ZcvEQio6nnrc1/X8B6Kcd6waeSNoVCfCH/y9Ff87CWphkgpRYaYOpf6OBPUPno
		B1Aa5tUJuoQjpCyl9OPI4d67tnzkwBa4t4iit+Dk4bYyqLXO+ra8co1uV/H3VVKe
		YcC/C1seNmwkZYZqAQJBANo1NKXU0IFlxzGroMe/tT+6SwztTfL4ExsuDUuiJdAy
		1oYJEbQq/7gXIS4yvkEWkCQIiXn02yhbHsLevXySUxECQQDBfIQgC+SqIfOvDeiE
		3oQtJ/Fsu2Z4kaWE8p7q/D34GcP2OJAj0DJYvaWPUGiljzQnHGBTz/LB/XtdONGw
		rk9dAkEAuxtMXbYyZAJl382PPDjCrjaMDDWf1Wuq1m+SrvwG+JPfJ2e3aopEZBJR
		PU/9m8pBJuS7HXw8QEqCAg8E5ECEQQJAIj/5X3bbfmZOLZGntEVzXk7wxI+TvwoB
		I7yS9wO5sH5XGvG+SiijkOPZN7pDG/Nyhu3V+2AXF9HYEZNqQv1IHQJAQ9klodKD
		DjS5gNnb7fxsSJ95+Hxt3Fz+bG3hqrqjzaVdSPUWbWYo8Jtu0zY8kmQaU5gg+hcj
		88w/68UftLlTzA==
		-----END PRIVATE KEY-----`)
)

// 初始化公钥和私钥对
func InitRsaKey() {
	rsaSertKey = privateKey2
	rsaSertKey = rsaPubKey
}

// 公钥加密
func RsaEncrypt(origData []byte) (string, error) {
	//fmt.Println("public key: ", string(pubKey))

	block, _ := pem.Decode(rsaPubKey)
	if block == nil {
		return "", errors.New("public key error")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}

	pub := pubInterface.(*rsa.PublicKey)

	encryptBytes, err := rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
	if err != nil {
		tmpStr := fmt.Sprintf("rsa encrypt err: %v", err)
		return "", errors.New(tmpStr)
	}

	baseEncryMsg := base64.StdEncoding.EncodeToString(encryptBytes)

	return baseEncryMsg, nil
}

// 私钥解密的时候，有可能是 s1 和 s8 两种对齐的, 需要轮流试
func RsaS8Decrypt(baseEncryMsg string) ([]byte, error) {
	block, _ := pem.Decode(rsaSertKey)
	if block == nil {
		return nil, errors.New("private key error!")
	}

	/// s8 对齐方式的解密
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		tmpStr := fmt.Sprintf("private s8 key err: %v", err)
		return nil, errors.New(tmpStr)
	}

	// s8 对齐的
	privKey := priv.(*rsa.PrivateKey)

	//base64 解码
	decryptMsg, err := base64.StdEncoding.DecodeString(baseEncryMsg)
	if err != nil {
		tmpStr := fmt.Sprintf("base64 decode err: %v", err)
		return nil, errors.New(tmpStr)
	}

	return rsa.DecryptPKCS1v15(rand.Reader, privKey, decryptMsg)
}

// 私钥解密 s1对齐方式解密
func RsaS1Decrypt(baseEncryMsg string) ([]byte, error) {
	block, _ := pem.Decode(rsaSertKey)
	if block == nil {
		return nil, errors.New("private key error!")
	}

	// s1对齐的方式解密
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		tmpStr := fmt.Sprintf("s1 private key err: %v", err)
		return nil, errors.New(tmpStr)
	}

	// base64 解码
	decryptMsg, err := base64.StdEncoding.DecodeString(baseEncryMsg)
	if err != nil {
		tmpStr := fmt.Sprintf("base64 decode err: %v", err)
		return nil, errors.New(tmpStr)
	}

	return rsa.DecryptPKCS1v15(rand.Reader, priv, decryptMsg)
}
