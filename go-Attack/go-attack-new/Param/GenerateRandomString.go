package Param

import (
	"math/rand"
	"time"
)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

// randomString 生成指定长度的随机字符串
func GenerateRandomString(length int) string {
	if length <= 0 {
		return ""
	}
	// 设置随机数种子
	rand.Seed(time.Now().UnixNano())

	// 用于存储生成的随机字符串
	b := make([]byte, length)
	for i := range b {
		// 从字符集中随机选择一个字符
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}
