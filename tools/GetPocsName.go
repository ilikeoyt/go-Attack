package tools

import (
	"os"
	"path/filepath"
	"strings"
)

func GetPocsNames(dirPath string) ([]string, error) {
	var fileNames []string

	// 使用 filepath.Walk 遍历目录及其子目录
	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		// 错误处理
		if err != nil {
			return err
		}

		// 如果是文件且文件名以 .yaml 结尾
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".yaml") {
			// 获取文件名（不带路径）
			fileName := info.Name()
			// 去掉文件扩展名
			fileNameWithoutExt := strings.TrimSuffix(fileName, filepath.Ext(fileName))

			// 将文件名添加到数组中
			fileNames = append(fileNames, fileNameWithoutExt)
		}

		return nil
	})

	// 返回文件名数组和可能发生的错误
	return fileNames, err
}
