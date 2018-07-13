package cryptology

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type MsgBodyData struct {
	MsgType int         `json:"msgType,omitempty"` // 消息类型
	Msg     interface{} `json:"msg,omitempty"`     // 消息体, 内容
}

func testaes1() {
	// AES-128。key长度：16, 24, 32 bytes 对应 AES-128, AES-192, AES-256
	key := []byte("auyn896ntgrbmz9w")

	data := &MsgBodyData{}
	data.MsgType = 1
	data.Msg = "hello"

	contentByte, err := json.Marshal(data)
	if err != nil {
		tmpStr := fmt.Sprintf("fmt to json err: %v", err)
		fmt.Println(tmpStr)
		return
	}

	// aes 加密
	result, err := AesEncrypt(contentByte, key)
	if err != nil {
		panic(err)
	}
	//fmt.Println("encrypt msg: ", string(result))
	encryptBase64 := base64.StdEncoding.EncodeToString(result)
	fmt.Printf("base64 len: %v, content: %v\n", len(encryptBase64), encryptBase64)

	// aes 解密
	origData, err := AesDecrypt(result, key)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(origData))
}

// aes 加密
func AesEncrypt(origData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()

	// 如果你不指定填充及加密模式的话，将会采用 ECB 模式和 PKCS5Padding 填充进行处理, 这里采用 pkcs5Padding
	origData = PKCS5Padding(origData, blockSize)

	// origData = ZeroPadding(origData, block.BlockSize())
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origData))

	// 根据CryptBlocks方法的说明，如下方式初始化crypted也可以
	// crypted := origData
	blockMode.CryptBlocks(crypted, origData)

	return crypted, nil
}

// aes 解密
func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origData := make([]byte, len(crypted))

	// origData := crypted
	blockMode.CryptBlocks(origData, crypted)
	origData = PKCS5UnPadding(origData)
	// origData = ZeroUnPadding(origData)

	return origData, nil
}

func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func ZeroUnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}
