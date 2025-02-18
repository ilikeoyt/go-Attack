package tools

import (
	"io"
	"strings"
)

func GetBodyLength(reqBody io.Reader) int {
	if reqBody == nil {
		return 0
	}

	// 尝试将 reqBody 转换为 strings.Reader 类型
	if strReader, ok := reqBody.(*strings.Reader); ok {
		return strReader.Len()
	}

	// 如果无法转换为 strings.Reader 类型，这里暂时返回 0，可根据实际情况扩展
	return 0
}
