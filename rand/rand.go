package pkgrand

import (
	cryRand "crypto/rand"
	"errors"
	"math/big"
	"math/rand"
	"strconv"
	"time"
)

/*************************************************
@ 获取伪随机数, 如： 00347135859b4561
@ size:随机数的长度
@ strType:
@ 1: 数字,大小写字母
@ 2: 纯数字
@ 3: 纯小写字母
@ 4: 纯大写字母
@ 5: 数字+小写字母
@ 6: 数字+ 大写字母
@ 7: 小写+大写字母
@**************************************************/
func GetRandStr(strType int, size int) string {
	var kinds [][]int
	switch strType {
	case 1:
		kinds = [][]int{[]int{10, 48}, []int{26, 97}, []int{26, 65}}
	case 2:
		kinds = [][]int{[]int{10, 48}}
	case 3:
		kinds = [][]int{[]int{26, 97}}
	case 4:
		kinds = [][]int{[]int{26, 65}}
	case 5:
		kinds = [][]int{[]int{10, 48}, []int{26, 97}}
	case 6:
		kinds = [][]int{[]int{10, 48}, []int{26, 65}}
	case 7:
		kinds = [][]int{[]int{26, 97}, []int{26, 65}}
	default:
		return ""
	}

	kindsLen := len(kinds)
	res := make([]byte, size)

	rand.Seed(time.Now().UnixNano())
	for i := 0; i < size; i++ {
		// random ikind
		ikind := rand.Intn(kindsLen)
		scope := kinds[ikind][0]
		base := kinds[ikind][1]

		res[i] = uint8(base + rand.Intn(scope))
	}

	return string(res)
}

// 获取一个某一个数字段的真随机数, 返回获取到的数据的 int64, string
func RandNum(minNum, maxNum int64) (int64, string, error) {
	if minNum > maxNum {
		return 0, "", errors.New("params invalid")
	} else if minNum == maxNum {
		return 0, strconv.FormatInt(minNum, 10), nil
	}

	maxBigInt := big.NewInt(maxNum)
	tmp, _ := cryRand.Int(cryRand.Reader, maxBigInt)
	tmpInt := tmp.Int64()

	if tmpInt >= minNum {
		return tmpInt, tmp.String(), nil
	}

	return RandNum(minNum, maxNum)
}
