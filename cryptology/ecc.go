package cryptology

import (
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

var (
	// openssl 命令如下:
	// 私钥: openssl ecparam -genkey -name prime256v1 -out eccPriKey.pem
	// 公钥: openssl ec -in eccPriKey.pem -pubout -out eccPubkey.pem
	eccPubKey1 = []byte(`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEpOZ0XvLQ2d6sraSrkFiBJzStmkQB
7zB1w9qyYgLJbZoHcvMpV4czqonE1zALtmKSfA6Rvm8EVHCObGvTQ/yH+A==
-----END PUBLIC KEY-----`)

	eccPriKey1 = []byte(`
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIO6igheFZJj9susF/o6lMMUl/wolxupOre38ajHXGxwOoAoGCCqGSM49
AwEHoUQDQgAEpOZ0XvLQ2d6sraSrkFiBJzStmkQB7zB1w9qyYgLJbZoHcvMpV4cz
qonE1zALtmKSfA6Rvm8EVHCObGvTQ/yH+A==
-----END EC PRIVATE KEY-----`)
)

func Testecc() {
	// len 43, 对应 256
	// randKey := "D4zM58Y703ZpEYqd87f34FgOzxe4wIpq63vXZOA9m9A"
	randSign := "58Y703e4wIpq63vXZO"

	// 生成 ecc 秘钥对
	// prk, puk, err := CreateEccKey(randKey)
	// if err != nil {
	// 	fmt.Println("creat ecc key err: ", err)
	// 	return
	// }

	// 初始化 ecc key
	prk, puk, err := InitEccKey(eccPubKey1, eccPriKey1)
	if err != nil {
		fmt.Println("init ecc key err: ", err)
		return
	}

	fmt.Println("puk: ", puk)

	text := "helloworld"
	//salt := "welcom"

	//hashBytes := hashtext(text, salt)
	hashBytes := []byte(text)
	//fmt.Println("hexEncode hashBytes: ", hex.EncodeToString(hashBytes))

	//hash值进行签名
	result, err := EccSign(hashBytes, randSign, prk)
	if err != nil {
		fmt.Println("sign err: ", err)
		return
	}
	//签名输出
	fmt.Printf("result len: %v, content: %v\n", len(result), result)

	//签名与hash值进行校验
	tmp, err := EccVerify(hashBytes, result, puk)
	fmt.Println("verify: ", tmp)
	if err != nil {
		fmt.Println("sign err: ", err)
		return
	}
	return
}

/*
通过一个随机key创建公钥和私钥
随机key至少为36位
*/
func CreateEccKey(randKey string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	var err error

	var prk *ecdsa.PrivateKey
	var puk *ecdsa.PublicKey
	var curve elliptic.Curve

	lenth := len(randKey)
	if lenth <= 224/8+8 {
		err = errors.New("private key too short, more than 36")
		return prk, puk, err
	}

	if lenth > 521/8+8 { // > 74
		curve = elliptic.P521()
	} else if lenth > 384/8+8 { // > 56
		curve = elliptic.P384()
	} else if lenth > 256/8+8 { // > 40
		curve = elliptic.P256()
	} else if lenth > 224/8+8 { // > 36
		fmt.Println("p224..........")
		curve = elliptic.P224()
	} else {
		return prk, puk, errors.New("key too short, more than 36")
	}

	prk, err = ecdsa.GenerateKey(curve, strings.NewReader(randKey))
	if err != nil {
		return prk, puk, err
	}

	//ecder, err := x509.MarshalECPrivateKey(prk)
	// keypem, err := os.OpenFile("ec-key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	// secp256r1, err := asn1.Marshal(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	// pem.Encode(keypem, &pem.Block{Type: "EC PARAMETERS", Bytes: secp256r1})

	puk = &prk.PublicKey

	//fmt.Println("prk: ", *prk)
	//fmt.Println("puk: ", puk)

	return prk, puk, err
}

// 初始化 ecc key
func InitEccKey(eccPubKey, eccPrk []byte) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	var prk *ecdsa.PrivateKey
	var puk *ecdsa.PublicKey
	//curve := elliptic.P256()
	//eccPubKey := eccPubKey1
	//eccPrk := eccPriKey1
	var err error
	ok := false

	//fmt.Println("ecc pubKey: ", string(eccPubKey))

	// x, y := elliptic.Unmarshal(curve, eccPubKey)

	// puk = ecdsa.PublicKey{}
	// puk.Curve = curve
	// puk.X = x
	// puk.Y = y

	// fmt.Printf("x: %v, y: %v\n", x, y)

	pubKeyblock, _ := pem.Decode(eccPubKey)
	if pubKeyblock == nil {
		return nil, puk, fmt.Errorf("public key error")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(pubKeyblock.Bytes)
	if err != nil {
		return nil, puk, err
	}
	puk, ok = pubInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, puk, errors.New("not ecdsa public key")
	}

	// ecdsa 私钥文件的读取
	block, _ := pem.Decode(eccPrk)
	if block == nil {
		tmpStr := fmt.Sprintf("ecc private pem decode err")
		return nil, puk, errors.New(tmpStr)
	}

	// data, err := x509.DecryptPEMBlock(block, []byte(``))
	// if err != nil {
	// 	tmpStr := fmt.Sprintf("ecc decrypt private pem  err")
	// 	fmt.Println(tmpStr)
	// 	return nil, puk, errors.New(tmpStr)
	// }

	prk, err = x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		tmpStr := fmt.Sprintf("parse ec private key err: %v", err)
		return nil, puk, errors.New(tmpStr)
	}

	//pukParse = prk.PublicKey

	return prk, puk, nil
}

/**
  hash加密
  使用md5加密
*/
func hashtext(text, salt string) []byte {
	Md5Inst := md5.New()
	Md5Inst.Write([]byte(text))
	result := Md5Inst.Sum([]byte(salt))

	return result
}

/**
  对text加密，text必须是一个hash值，例如md5、sha1等
  使用私钥prk
  使用随机熵增强加密安全，安全依赖于此熵，randsign
  返回加密结果，结果为数字证书r、s的序列化后拼接，然后用hex转换为string
*/
func EccSign(text []byte, randSign string, prk *ecdsa.PrivateKey) (string, error) {
	r, s, err := ecdsa.Sign(strings.NewReader(randSign), prk, text)
	if err != nil {
		return "", err
	}
	rt, err := r.MarshalText()
	if err != nil {
		return "", err
	}
	st, err := s.MarshalText()
	if err != nil {
		return "", err
	}
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	defer w.Close()
	_, err = w.Write([]byte(string(rt) + "+" + string(st)))
	if err != nil {
		return "", err
	}
	w.Flush()

	//return hex.EncodeToString(b.Bytes()), nil

	// 采用 base64编码
	return base64.StdEncoding.EncodeToString(b.Bytes()), nil
}

/**
  校验文本内容是否与签名一致
  使用公钥校验签名和文本内容
*/
func EccVerify(text []byte, signature string, key *ecdsa.PublicKey) (bool, error) {

	rint, sint, err := GetEccSign(signature)
	if err != nil {
		return false, err
	}
	result := ecdsa.Verify(key, text, &rint, &sint)
	return result, nil
}

/**
  证书分解
  通过hex解码，分割成数字证书r，s
*/
func GetEccSign(signature string) (rint, sint big.Int, err error) {
	// byterun, err := hex.DecodeString(signature)
	// if err != nil {
	// 	err = errors.New("decrypt error, " + err.Error())
	// 	return
	// }

	byterun, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		err = errors.New("decrypt error, " + err.Error())
		return
	}

	r, err := gzip.NewReader(bytes.NewBuffer(byterun))
	if err != nil {
		err = errors.New("decode error," + err.Error())
		return
	}
	defer r.Close()
	buf := make([]byte, 1024)
	count, err := r.Read(buf)
	if err != nil {
		err = errors.New("decode read error," + err.Error())
		return
	}
	rs := strings.Split(string(buf[:count]), "+")
	if len(rs) != 2 {
		err = errors.New("decode fail")
		return
	}
	err = rint.UnmarshalText([]byte(rs[0]))
	if err != nil {
		err = errors.New("decrypt rint fail, " + err.Error())
		return
	}
	err = sint.UnmarshalText([]byte(rs[1]))
	if err != nil {
		err = errors.New("decrypt sint fail, " + err.Error())
		return
	}

	return
}
