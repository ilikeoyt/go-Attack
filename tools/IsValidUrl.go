package tools

import (
	"crypto/tls"
	"net/http"
	"time"
)

func IsValidURL(url string) bool {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get(url)

	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return true
}
