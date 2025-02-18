package Param

import (
	"math/rand"
	"strconv"
	"time"
)

func GenerateRandomNumber(digits int) string {
	if digits <= 0 {
		return "0"
	}
	// 设置随机数种子，确保每次运行结果不同
	rand.Seed(time.Now().UnixNano())

	// 计算最小和最大的数字
	min := 1
	for i := 1; i < digits; i++ {
		min *= 10
	}
	max := min*10 - 1

	// 生成随机数
	randomNum := rand.Intn(max-min+1) + min

	// 将随机数转换为字符串
	return strconv.Itoa(randomNum)
}
