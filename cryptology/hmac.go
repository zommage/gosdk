package cryptology

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

/*****************************************
@  hmac 的签名算法
@  secret: 秘钥, 如: xgHdj786Y22nnbbh
@  method: 请求方法
@  params: 请求参数
@  return: 处理过后的路由参数, 加上一个签名参数
@****************************************/
func SignatureParams(secret, method string, params map[string]interface{}) (string, error) {
	sigUrl := method + "&" + url.QueryEscape("/") + "&"
	urlEncode := ""

	var keys []string
	for k, _ := range params {
		keys = append(keys, k)
	}

	//对参数进行排序
	sort.Strings(keys)
	isfirst := true
	for _, key := range keys {
		if !isfirst {
			urlEncode = urlEncode + "&"
		}
		isfirst = false

		value := typeToString(params[key])

		// url编码各语言对空格的处理方法不一样, golang 是直接转为+号, js是转为 20%,这里统一去掉空格
		value = strings.Replace(value, " ", "", -1)

		//对url进行encode
		key = url.QueryEscape(key)
		value = url.QueryEscape(value)
		params[key] = value

		urlEncode = urlEncode + key + "=" + value
	}

	// 对整个url进行编码
	sigUrl = sigUrl + url.QueryEscape(urlEncode)

	// 获得签名
	sig, _ := sign(sigUrl, secret+"&")

	return sig, nil
}

// 进行签名和 base64编码
func sign(signPlainText string, secret string) (string, string) {
	key := []byte(secret)

	hash := hmac.New(sha1.New, key)
	hash.Write([]byte(signPlainText))
	sig := base64.StdEncoding.EncodeToString([]byte(string(hash.Sum(nil))))
	encodeSig := url.QueryEscape(sig)

	return sig, encodeSig
}

// 类型转换为 string
func typeToString(t interface{}) string {
	switch v := t.(type) {
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case string:
		return v
	case float32:
		return strconv.FormatFloat(float64(v), 'E', -1, 32)
	case float64:
		return strconv.FormatFloat(v, 'E', -1, 64)
	default:
		return ""
	}
}
