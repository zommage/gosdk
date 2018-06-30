package httpclient

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

var (
	HttpClient       *http.Client // 不过滤掉证书检查的 http client
	SkipVerifyClient *http.Client // 过滤掉证书的  http client
)

// init HTTPClient  默认开启长链接(http 1.1之后) 开启http keepalive功能，也即是否重用连接，
func init() {
	HttpClient = createHTTPClient(true)
	SkipVerifyClient = createHTTPClient(false)
}

const (
	MaxIdleConns        int = 5000 // 连接池对所有host的最大链接数量，host也即dest-ip, 默认 100
	MaxIdleConnsPerHost int = 2000 // 连接池对每个host的最大链接数量
	IdleConnTimeout     int = 90   // 空闲timeout设置，也即socket在该时间内没有交互则自动关闭连接（注意：该timeout起点是从每次空闲开始计时，若有交互则重置为0）,该参数通常设置为分钟级别
	RequestTimeout      int = 30   // 请求以及连接的超时时间
)

// createHTTPClient for connection re-use
func createHTTPClient(verifyFlag bool) *http.Client {
	if verifyFlag != true {
		return &http.Client{
			Transport: &http.Transport{
				Proxy:           http.ProxyFromEnvironment,
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: (&net.Dialer{
					Timeout:   time.Duration(RequestTimeout) * time.Second,
					KeepAlive: time.Duration(RequestTimeout) * time.Second,
				}).DialContext,

				MaxIdleConns:        MaxIdleConns,
				MaxIdleConnsPerHost: MaxIdleConnsPerHost,
				IdleConnTimeout:     time.Duration(IdleConnTimeout) * time.Second,
			},

			Timeout: time.Duration(RequestTimeout) * time.Second,
		}
	} else {
		return &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   time.Duration(RequestTimeout) * time.Second,
					KeepAlive: time.Duration(RequestTimeout) * time.Second,
				}).DialContext,

				MaxIdleConns:        MaxIdleConns,
				MaxIdleConnsPerHost: MaxIdleConnsPerHost,
				IdleConnTimeout:     time.Duration(IdleConnTimeout) * time.Second,
			},

			Timeout: time.Duration(RequestTimeout) * time.Second,
		}
	}
}

// 发送 form 表单的请求
func SendFormDataHttp(method, url string, params map[string]interface{}, verifyFlag bool) ([]byte, error) {
	var err error
	var respBytes []byte

	for i := 0; i < 5; i++ {
		respBytes, err = SendFormReq(method, url, params, verifyFlag)
		if err != nil {
			if i < 4 {
				time.Sleep(time.Duration(i+1) * time.Second)
				continue
			}
			tmpStr := fmt.Sprintf("req err: %v", err)
			return nil, errors.New(tmpStr)
		}
		return respBytes, nil
	}

	return nil, errors.New("run err")
}

// 发送 form 表单的请求
func SendFormReq(method, url string, params map[string]interface{}, verifyFlag bool) ([]byte, error) {
	var r http.Request
	r.ParseForm()

	for k, v := range params {
		r.Form.Add(k, fmt.Sprintf("%v", v))
	}

	bodystr := strings.TrimSpace(r.Form.Encode())
	request, err := http.NewRequest(method, url, strings.NewReader(bodystr))
	if err != nil {
		return nil, err
	}

	var resp *http.Response
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	//request.Header.Set("Connection", "Keep-Alive")

	if verifyFlag != true {
		resp, err = SkipVerifyClient.Do(request)
	} else {
		resp, err = HttpClient.Do(request)
	}

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		tmpStr := fmt.Sprintf("resp fmt bytes err: %v", err)
		return nil, errors.New(tmpStr)
	}

	return respBytes, nil
}

// 发送一般的请求
func SendHttp(method, url string, data io.Reader, verifyFlag bool) ([]byte, error) {
	var err error
	var respBytes []byte

	for i := 0; i < 5; i++ {
		respBytes, err = SendReq(method, url, data, verifyFlag)
		if err != nil {
			if i < 4 {
				time.Sleep(time.Duration(i+1) * time.Second)
				continue
			}
			tmpStr := fmt.Sprintf("req err: %v", err)
			return nil, errors.New(tmpStr)
		}
		return respBytes, nil
	}

	return nil, errors.New("run err")
}

// 发送请求
func SendReq(method, url string, data io.Reader, verifyFlag bool) ([]byte, error) {
	request, err := http.NewRequest(method, url, data)
	if err != nil {
		return nil, err
	}

	var resp *http.Response

	if verifyFlag != true {
		resp, err = SkipVerifyClient.Do(request)
	} else {
		resp, err = HttpClient.Do(request)
	}

	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		tmpStr := fmt.Sprintf("resp fmt bytes err: %v", err)
		return nil, errors.New(tmpStr)
	}

	return respBytes, nil
}
