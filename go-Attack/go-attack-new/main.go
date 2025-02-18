package main

import (
	"flag"
	"fmt"
	"go-attack-new/request"
	"go-attack-new/tools"
	"strings"
	"sync"
)

var Banner string = `
 ____  _     _____ ____        ____  _____  _____  ____  _  __
/   _\/ \ |\/  __// ___\      /  _ \/__ __\/__ __\/   _\/ |/ /
|  /  | | //|  \  ||___ _____ | / \|  / \    / \  |  /  |   /
|  \__| \// |  /_ \___ |\____\| |-||  | |    | |  |  \_ |   \
\____/\__/  \____\\____/      \_/ \|  \_/    \_/  \____/\_|\_\
  
               ____ ___  _  ___  _ ____ ___  _ _     ____     
              /  _ \\  \//  \  \///   _\\  \/// \   /  _ \    
        _____ | | // \  /    \  / |  /   \  / | |   | / \|    
        \____\| |_\\ / /     / /  |  \_  /  \ | |_/\| \_/|    
              \____//_/     /_/   \____//__/\\\____/\____`

func main() {
	urlFlag := flag.String("u", "", "目标url")
	ListFlag := flag.String("list", "", "目标urls文件")
	ShowFlag := flag.Bool("show", false, "展示所有支持漏洞")
	AttackFlag := flag.Bool("attack", false, "是否加入攻击参数")
	VulnFlag := flag.String("vuln", "", "指定漏洞名称")

	flag.Parse()

	Show := *ShowFlag
	Vuln := *VulnFlag
	attackFlag := *AttackFlag
	var validUrls []string

	PocPath := "POCs" // 这里的路径可以根据需要更改
	fileNames, err := tools.GetPocsNames(PocPath)

	if Show {
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		for _, fileName := range fileNames {
			fmt.Println(fileName) // 每次输出一个文件名，换行
		}
		return
	}

	if *urlFlag == "" && *ListFlag == "" {
		fmt.Println("请输入目标url或url列表,参数-u或-l")
		return
	}

	url := strings.TrimSuffix(*urlFlag, "/")

	allUrls, _ := tools.ReadURLsFromFile(*ListFlag)

	if url != "" && tools.IsValidURL(url) {
		var wg sync.WaitGroup
		fmt.Println(Banner)
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}

		wg.Add(1)
		go request.ScanURL(url, attackFlag, fileNames, PocPath, Vuln, &wg)

		// 等待所有 goroutine 完成
		wg.Wait()
	} else if *ListFlag != "" {
		var wg sync.WaitGroup

		fmt.Println(Banner)

		for _, url := range allUrls {
			if tools.IsValidURL(url) {
				validUrls = append(validUrls, url)
			}
		}

		// 对每个 URL 启动一个 goroutine 进行扫描
		for _, url := range validUrls {
			wg.Add(1)
			go request.ScanURL(url, attackFlag, fileNames, PocPath, Vuln, &wg)
		}

		// 等待所有 goroutine 完成
		wg.Wait()
	}

	return
}
