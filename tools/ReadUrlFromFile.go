package tools

import (
	"bufio"
	"os"
	"strings"
)

func ReadURLsFromFile(filePath string) ([]string, error) {
	var urls []string

	// 打开 urls.txt 文件
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// 使用 scanner 按行读取文件
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		// 忽略空行和注释行
		if url != "" && !strings.HasPrefix(url, "#") {
			url = strings.TrimSuffix(url, "/")
			// 处理 URL，确保以 http:// 或 https:// 开头
			if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
				url = "http://" + url
			}
			urls = append(urls, url)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}
