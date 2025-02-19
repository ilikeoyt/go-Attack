package request

import (
	"go-attack-new/ConLoad"
	"sync"
)

func ScanURL(url string, attackFlag bool, fileNames []string, PocPath string, Vuln string, proxy string, dynamic bool, wg *sync.WaitGroup) {
	defer wg.Done()

	errorLogger := ConLoad.CreateErrorLog()
	defer ConLoad.CloseLogFile()

	// 动态渲染预处理
	if dynamic {
		browser, err := NewBrowser()
		if err != nil {
			errorLogger.Printf("Failed to init browser for %s: %v", url, err)
			return
		}
		defer browser.cancel()
		
		dom, requests, err := browser.RenderFullDOM(url)
		if err == nil {
			// 将动态内容转换为静态请求
			url = processDynamicContent(dom, requests)
		}
	}
	
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
