package request

import (
	"go-attack-new/ConLoad"
	"sync"
)

func ScanURL(url string, attackFlag bool, fileNames []string, PocPath string, Vuln string, proxy string, wg *sync.WaitGroup) {
	defer wg.Done()

	errorLogger := ConLoad.CreateErrorLog()
	defer ConLoad.CloseLogFile() // 确保程序退出时关闭日志文件
	// 遍历每个 POC 文件
	if Vuln == "" {
		for _, fileName := range fileNames {
			FullFileName := PocPath + "/" + fileName + ".yaml"
			// 调用 FinalRes 扫描每个 URL
			ResErr := FinalReq(url, attackFlag, FullFileName, proxy)
			if ResErr != nil {
				errorLogger.Printf("Error scanning %s: %v", url, ResErr)
			}
		}
	} else {
		FullFileName := PocPath + "/" + Vuln + ".yaml"
		ResErr := FinalReq(url, attackFlag, FullFileName, proxy)
		if ResErr != nil {
			errorLogger.Printf("Error scanning %s: %v", url, ResErr)
		}
	}
}
