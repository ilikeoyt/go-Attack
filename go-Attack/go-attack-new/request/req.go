package request

import (
	"crypto/tls"
	"go-attack-new/ConLoad"
	"go-attack-new/Judge"
	"go-attack-new/Param"
	"go-attack-new/tools"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func FinalReq(ReqUrl string, attackFlag bool, filename string) error {
	var matchType string
	var ReqPath string
	var Timeout int
	var httpMethod string
	var headers map[string]string
	var data string
	var randomStringLen int
	var MatchOnlyHeaders string
	var randomNumberLen int
	var body []byte
	var rspHeaders http.Header
	var rspTime time.Duration

	proxyURL, err5 := url.Parse("http://127.0.0.1:8080")
	if err5 != nil {
		return err5
	}
	config, err1 := ConLoad.LoadConfig(filename)
	if err1 != nil {
		return err1
	}

	for _, match := range config.Match {
		matchType = match.Type
	}

	for _, match := range config.MatchHeaders {
		MatchOnlyHeaders = match.MatchOnlyHeaders
	}

	for _, match := range config.Param {
		randomStringLen = match.RandomString
	}
	randomString := Param.GenerateRandomString(randomStringLen)

	for _, match := range config.Param {
		randomNumberLen = match.RandomNumber
	}
	randomNumber := Param.GenerateRandomNumber(randomNumberLen)

	for _, match := range config.Requests {
		ReqPath = match.ReqPath
		Timeout = match.Timeout
		httpMethod = match.HttpMethod
		headers = match.Headers
		data = match.Data

		// 替换 ReqPath 中的 ${{randomString}}
		ReqPath = strings.ReplaceAll(ReqPath, "${{randomString}}", randomString)
		// 替换 headers 中的 ${{randomString}}
		for key, value := range headers {
			headers[key] = strings.ReplaceAll(value, "${{randomString}}", randomString)
		}
		// 替换 data 中的 ${{randomString}}
		data = strings.ReplaceAll(data, "${{randomString}}", randomString)

		// 替换 ReqPath 中的 ${{randomNumber}}
		ReqPath = strings.ReplaceAll(ReqPath, "${{randomNumber}}", randomNumber)
		// 替换 headers 中的 ${{randomNumber}}
		for key, value := range headers {
			headers[key] = strings.ReplaceAll(value, "${{randomNumber}}", randomNumber)
		}
		// 替换 data 中的 ${{randomNumber}}
		data = strings.ReplaceAll(data, "${{randomNumber}}", randomNumber)

		CompleteUrl := ReqUrl + ReqPath
		tr := &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			Proxy:           http.ProxyURL(proxyURL),
		}

		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: tr,
			Timeout:   time.Duration(Timeout) * time.Second,
		}

		// 根据 httpMethod 和 data 创建请求体
		var reqBody io.Reader
		if httpMethod == "POST" {
			reqBody = strings.NewReader(data)
		} else {
			reqBody = nil
		}

		// 创建 HTTP 请求
		request, err2 := http.NewRequest(httpMethod, CompleteUrl, reqBody)
		if err2 != nil {
			return err2
		}
		// 自动创建Content-length
		if reqBody != nil {
			request.Header.Set("Content-Length", strconv.Itoa(tools.GetBodyLength(reqBody)))
		}
		for key, value := range headers {
			request.Header.Set(key, value)
		}

		// 记录请求开始时间
		startTime := time.Now()
		response, err3 := client.Do(request)
		if err3 != nil {
			return err3
		}
		// 记录请求结束时间
		endTime := time.Now()

		body, _ = io.ReadAll(response.Body)
		rspHeaders = response.Header
		rspTime = endTime.Sub(startTime)

		defer response.Body.Close()
	}

	if MatchOnlyHeaders == "true" {
		matchHeaderRes := Judge.HeaderStringJudgeRes(rspHeaders, filename, randomString, randomNumber)
		if matchHeaderRes == true {
			err := tools.MessageOutput(filename, attackFlag, ReqUrl)
			if err != nil {
				return err
			}
		} else {
			return nil
		}
	}

	if MatchOnlyHeaders == "false" {
		matchHeaderRes := Judge.HeaderStringJudgeRes(rspHeaders, filename, randomString, randomNumber)
		matchRes := Judge.StringJudgeRes(string(body), filename, randomString, randomNumber)
		if matchHeaderRes == true && matchRes == true {
			err := tools.MessageOutput(filename, attackFlag, ReqUrl)
			if err != nil {
				return err
			}
		} else {
			return nil
		}
	}

	if matchType == "String" {
		matchRes := Judge.StringJudgeRes(string(body), filename, randomString, randomNumber)
		if matchRes == true {
			err := tools.MessageOutput(filename, attackFlag, ReqUrl)
			if err != nil {
				return err
			}
		}
	} else if matchType == "Time" {
		err := Judge.TimeJudgeRes(rspTime, ReqUrl, attackFlag, filename)
		if err != nil {
			return err
		}
	}

	return nil
}
