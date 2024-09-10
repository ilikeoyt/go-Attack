package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"go-Attack/CVEs"
	"io/ioutil"
	"net/http"
	"strings"
	"sync"
)

var functionNames = []string{
	"CVE-2024-1021",
	"CVE-2024-28895",
	"CVE-2024-3400",
	"CVE-2024-32709",
	"CVE-2024-36991",
	"CVE-2024-5084",
	"CVE-2024-36401",
	"CVE-2024-23692",
	"CVE-2024-0195",
	"CVE-2024-31982",
	"CVE-2024-39943",
	"CVE-2024-4879",
	"CVE-2024-5217",
	"CVE-2024-5178",
	"CVE-2024-40050",
	"QVD-2024-26136",
	"CNVD-2024-15077",
	"CVE-2024-39914",
	"CVE-2024-32238",
	"KTO_SQLInjection",
	"KoronAIO_SQLInjection",
	"FanRuan_RCE",
	"JinHeOA_ArbitraryFileReading",
	"GuangLianDaOA_XXE",
	"RuiMingCrocus_ArbitraryFileReading",
	"SaiLan_ArbitraryFileReading",
	"XunRaoKeJiX2_AddUser",
	"CVE-2024-6646",
	"LanLinOA_RCE",
	"QuanXiAI_RCE",
	"YiTianZhiNeng_AnyUserAdd",
	"HuaLeiKeJiWuLiu_SQLInjection",
	"YongYouShiKongKSOA_SQLInjection",
	"TianWenWuYeERP_ArbitraryFileRead",
	"SaiLan_ArbitraryFileReading2",
	"HuiZhiERP_ArbitraryFileReading",
	"DingDianRuanJianLiveBos_AnyFileUpload",
	"HaiKangWeiShi_CommandInjection",
	"RAISECOM_RCE",
	"CVE-2024-2014",
	"XVE-2024-18926",
	"CVE-2024-38856",
	"YongYouShiKongKSOA_SQLInjection2",
	"XVE-2024-16919",
	"YiJieOA_AnyFileRead",
	"CVE-2024-6781",
	"CVE-2024-6782",
	"jmreport_PrivilegeBypass",
	"WanHuezOffice_SQLInjection",
	"YiSaiTong_UnauthorizedDeserialization",
	"YiSaiTong_SQLInjection",
	"CVE_2024_21733",
	"WookTeam_SQLInjection",
	"CVE-2024-23897",
	"CVE-2024-4956",
	"CVE-2024-6893",
	"FanWeieoffice10_SensitiveInformationDisclosure",
	"YongYouNCFileUpload",
	"CVE-2024-7928",
	"CVE-2024-7954",
	"CVE-2020-9496",
	"CVE-2023-49070",
}

var Attack bool
var FileData string
var Show bool
var CVE string
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

var cveFunctionMap = map[string]func(string, bool) error{
	"CVE-2024-1021":                                  CVEs.CVE_2024_1021,
	"CVE-2024-28895":                                 CVEs.CVE_2024_28895,
	"CVE-2024-3400":                                  CVEs.CVE_2024_3400,
	"CVE-2024-32709":                                 CVEs.CVE_2024_32709,
	"CVE-2024-36991":                                 CVEs.CVE_2024_36991,
	"CVE-2024-5084":                                  CVEs.CVE_2024_5084,
	"CVE-2024-36401":                                 CVEs.CVE_2024_36401,
	"CVE-2024-23692":                                 CVEs.CVE_2024_23692,
	"CVE-2024-0195":                                  CVEs.CVE_2024_0195,
	"CVE-2024-31982":                                 CVEs.CVE_2024_31982,
	"CVE-2024-39943":                                 CVEs.CVE_2024_39943,
	"CVE-2024-4879":                                  CVEs.CVE_2024_4879,
	"CVE-2024-5217":                                  CVEs.CVE_2024_5217,
	"CVE-2024-5178":                                  CVEs.CVE_2024_5178,
	"CVE-2024-40050":                                 CVEs.CVE_2024_40050,
	"QVD-2024-26136":                                 CVEs.QVD_2024_26136,
	"CNVD-2024-15077":                                CVEs.CNVD_2024_15077,
	"CVE-2024-39914":                                 CVEs.CVE_2024_39914,
	"CVE-2024-32238":                                 CVEs.CVE_2024_32238,
	"KTO-SQLInjection":                               CVEs.KTO_SQLInjection,
	"KoronAIO-SQLInjection":                          CVEs.KoronAIO_SQLInjection,
	"FanRuan-RCE":                                    CVEs.FanRuan_RCE,
	"JinHeOA-ArbitraryFileReading":                   CVEs.JinHeOA_ArbitraryFileReading,
	"GuangLianDaOA-XXE":                              CVEs.GuangLianDaOA_XXE,
	"RuiMingCrocus-ArbitraryFileReading":             CVEs.RuiMingCrocus_ArbitraryFileReading,
	"SaiLan-ArbitraryFileReading":                    CVEs.SaiLan_ArbitraryFileReading,
	"XunRaoKeJiX2-AddUser":                           CVEs.XunRaoKeJiX2_AddUser,
	"CVE-2024-6646":                                  CVEs.CVE_2024_6646,
	"LanLinOA_RCE":                                   CVEs.LanLinOA_RCE,
	"QuanXiAI_RCE":                                   CVEs.QuanXiAI_RCE,
	"YiTianZhiNeng_AnyUserAdd":                       CVEs.YiTianZhiNeng_AnyUserAdd,
	"HuaLeiKeJiWuLiu_SQLInjection":                   CVEs.HuaLeiKeJiWuLiu_SQLInjection,
	"YongYouShiKongKSOA_SQLInjection":                CVEs.YongYouShiKongKSOA_SQLInjection,
	"TianWenWuYeERP_ArbitraryFileRead":               CVEs.TianWenWuYeERP_ArbitraryFileRead,
	"SaiLan_ArbitraryFileReading2":                   CVEs.SaiLan_ArbitraryFileReading2,
	"HuiZhiERP_ArbitraryFileReading":                 CVEs.HuiZhiERP_ArbitraryFileReading,
	"DingDianRuanJianLiveBos_AnyFileUpload":          CVEs.DingDianRuanJianLiveBos_AnyFileUpload,
	"HaiKangWeiShi_CommandInjection":                 CVEs.HaiKangWeiShi_CommandInjection,
	"RAISECOM_RCE":                                   CVEs.RAISECOM_RCE,
	"CVE-2024-2014":                                  CVEs.CVE_2024_2014,
	"XVE-2024-18926":                                 CVEs.XVE_2024_18926,
	"CVE-2024-38856":                                 CVEs.CVE_2024_38856,
	"YongYouShiKongKSOA_SQLInjection2":               CVEs.YongYouShiKongKSOA_SQLInjection2,
	"XVE-2024-16919":                                 CVEs.XVE_2024_16919,
	"YiJieOA_AnyFileRead":                            CVEs.YiJieOA_AnyFileRead,
	"CVE-2024-6781":                                  CVEs.CVE_2024_6781,
	"CVE-2024-6782":                                  CVEs.CVE_2024_6782,
	"jmreport_PrivilegeBypass":                       CVEs.Jmreport_PrivilegeBypass,
	"WanHuezOffice_SQLInjection":                     CVEs.WanHuezOffice_SQLInjection,
	"YiSaiTong_UnauthorizedDeserialization":          CVEs.YiSaiTong_UnauthorizedDeserialization,
	"YiSaiTong_SQLInjection":                         CVEs.YiSaiTong_SQLInjection,
	"CVE_2024_21733":                                 CVEs.CVE_2024_21733,
	"WookTeam_SQLInjection":                          CVEs.WookTeam_SQLInjection,
	"CVE-2024-23897":                                 CVEs.CVE_2024_23897,
	"CVE-2024-4956":                                  CVEs.CVE_2024_4956,
	"CVE-2024-6893":                                  CVEs.CVE_2024_6893,
	"FanWeieoffice10_SensitiveInformationDisclosure": CVEs.FanWeieoffice10_SensitiveInformationDisclosure,
	"YongYouNCFileUpload":                            CVEs.YongYouNCFileUpload,
	"CVE-2024-7928":                                  CVEs.CVE_2024_7928,
	"CVE-2024-7954":                                  CVEs.CVE_2024_7954,
	"CVE-2020-9496":                                  CVEs.CVE_2020_9496,
	"CVE-2023-49070":                                 CVEs.CVE_2023_49070,
}

func main() {
	urlFlag := flag.String("u", "", "目标url")
	ListFlag := flag.String("list", "", "目标urls文件")
	ShowFlag := flag.Bool("show", false, "展示所有支持漏洞")
	AttckFlag := flag.Bool("attack", false, "是否加入攻击参数")
	CVEFlag := flag.String("cve", "", "指定CVE名称")
	CookieFlag := flag.String("cookie", "", "设置cookie")

	flag.Parse()

	Attack = *AttckFlag
	CVEs.Cookie = *CookieFlag
	Show = *ShowFlag
	CVE = *CVEFlag

	if Show {
		for _, name := range functionNames {
			fmt.Println(name)
		}
		return
	}

	if *urlFlag == "" && *ListFlag == "" {
		fmt.Println("请输入目标url或url列表,参数-u或-l")
		return
	}

	if *urlFlag != "" && *ListFlag == "" {
		url := strings.TrimSuffix(*urlFlag, "/")
		if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
			url = "http://" + url
		}

		fmt.Println(Banner)
		if !isValidURL(url) {
			return
		}
		var wg sync.WaitGroup
		results := make(chan error)

		if CVE != "" {
			if cveFunc, exists := cveFunctionMap[CVE]; exists {
				wg.Add(1)
				go func() {
					defer wg.Done()
					err := cveFunc(url, Attack)
					results <- err
				}()
			} else {
				fmt.Printf("无效的CVE函数名称: %s\n", CVE)
				return
			}
		} else {
			for _, cvefunc := range cveFunctionMap {
				wg.Add(1)
				go func(cvefunc func(string, bool) error) {
					defer wg.Done()
					err := cvefunc(url, Attack)
					results <- err
				}(cvefunc)
			}
		}

		go func() {
			wg.Wait()
			close(results)
		}()

		for err := range results {
			if err != nil {
				fmt.Print("")
			}
		}

		return
	} else {
		fileData, err := ioutil.ReadFile(*ListFlag)
		if err != nil {
			fmt.Println("url文件错误")
			return
		}
		FileData := string(fileData)
		urls := strings.Split(FileData, "\n")
		fmt.Println(Banner)

		var wg sync.WaitGroup
		results := make(chan error)

		for _, Targeturl := range urls {
			wg.Add(1)
			go func(Targeturl string) {
				defer wg.Done()
				Targeturl = strings.TrimSpace(Targeturl)
				Targeturl = strings.TrimSuffix(Targeturl, "/")
				if Targeturl != "" {
					if !strings.HasPrefix(Targeturl, "http://") && !strings.HasPrefix(Targeturl, "https://") {
						Targeturl = "http://" + Targeturl
					}
					if !isValidURL(Targeturl) {
						return
					}

					if CVE != "" {
						if cveFunc, exists := cveFunctionMap[CVE]; exists {
							err := cveFunc(Targeturl, Attack)
							results <- err
						} else {
							fmt.Printf("无效的CVE函数名称: %s\n", CVE)
							return
						}
					} else {
						for _, cvefunc := range cveFunctionMap {
							defer func() {
								if r := recover(); r != nil {
									fmt.Println(r)
								}
							}()
							err := cvefunc(Targeturl, Attack)
							results <- err
							if err != nil {
								fmt.Print("")
							}
						}
					}
				}
			}(Targeturl)
		}

		go func() {
			wg.Wait()
			close(results)
		}()

		for err := range results {
			if err != nil {
				fmt.Print("")
			}
		}

		return
	}
}

func isValidURL(url string) bool {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	resp, err := client.Get(url)

	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return true
}
