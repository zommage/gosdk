package pkgregexp

import (
	"errors"
	"fmt"
	"regexp"
)

/*************************************************
@ 校验函数
@ minLen: 最小长度
@ maxLen: 最大长度
@ str: 需要校验的字符串
@ regexpStr: 正则表达式
@ return error: 错误
@**************************************************/
func CheckFunc(minLen, maxLen int, str, regexpStr string) error {
	strLen := len(str)
	if strLen < minLen || strLen > maxLen {
		return fmt.Errorf("the length is invalid, %v-%v", minLen, maxLen)
	}

	// 判断正则表达式是否有误
	regCom, err := regexp.Compile(regexpStr)
	if err != nil {
		tmpStr := fmt.Sprintf("expression of regexp=%v is err: %v", regexpStr, err)
		return errors.New(tmpStr)
	}

	// 对 string 进行校验
	matchFlag := regCom.MatchString(str)
	if !matchFlag {
		tmpStr := fmt.Sprintf("params not match, is invalid")
		return errors.New(tmpStr)
	}

	return nil
}

// 数字和字母
func NumLetter(minLen, maxLen int, str string) error {
	regexpStr := "^[a-zA-Z0-9]*$"

	return CheckFunc(minLen, maxLen, str, regexpStr)
}

// 以数字和字母开头,包含下划线和扛
func NumLetterLine(minLen, maxLen int, str string) error {
	regexpStr := "^[a-zA-Z0-9][a-zA-Z0-9_-]*$"

	return CheckFunc(minLen, maxLen, str, regexpStr)
}

// 密码校验
func PwdCheck(minLen, maxLen int, str string) error {
	regexpStr := "^(?=.*?[a-zA-Z])(?=.*?[0-9])$"

	return CheckFunc(minLen, maxLen, str, regexpStr)
}

// 包含以 . 结尾的域名
func DomainCheckSufPoint(minLen, maxLen int, str string) error {
	regexpStr := "^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\\.?$"
	return CheckFunc(minLen, maxLen, str, regexpStr)
}

// 不包含以 . 结尾的域名
func DomainCheck(minLen, maxLen int, str string) error {
	regexpStr := "^[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+$"
	return CheckFunc(minLen, maxLen, str, regexpStr)
}
