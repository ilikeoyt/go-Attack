package request

import (
	"fmt"
	"strings"

	"golang.org/x/net/html"
)

func processDynamicContent(dom string, requests []NetworkRequest) string {
	// 提取关键端点
	endpoints := extractEndpoints(requests)

	// 解析DOM表单
	forms := parseForms(dom)

	// 合并动态参数
	params := mergeDynamicParams(endpoints, forms)

	// 构造最终请求参数
	return buildRequestURL(params)
}

func extractEndpoints(requests []NetworkRequest) map[string]string {
	endpoints := make(map[string]string)

	for _, req := range requests {
		if req.Method == "POST" && req.PostData != "" {
			endpoints[req.URL] = req.PostData
		} else if req.Method == "GET" && strings.Contains(req.URL, "?") {
			endpoints[req.URL] = strings.SplitN(req.URL, "?", 2)[1]
		}
	}
	return endpoints
}

func findFirstOption(n *html.Node) string {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.ElementNode && c.Data == "option" {
			// 优先返回value属性，没有则返回文本内容
			var value string
			for _, attr := range c.Attr {
				if attr.Key == "value" {
					value = attr.Val
					break
				}
			}
			if value == "" {
				// 提取option的文本内容
				if c.FirstChild != nil && c.FirstChild.Type == html.TextNode {
					value = strings.TrimSpace(c.FirstChild.Data)
				}
			}
			return value
		}
	}
	return "default"
}

func parseForms(dom string) map[string]string {
	forms := make(map[string]string)
	doc, err := html.Parse(strings.NewReader(dom))
	if err != nil {
		return forms
	}

	var parseForm func(*html.Node)
	parseForm = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			var action string
			for _, attr := range n.Attr {
				if attr.Key == "action" {
					action = attr.Val
					break
				}
			}

			var params []string
			var f func(*html.Node)
			f = func(n *html.Node) {
				if n.Type == html.ElementNode {
					switch n.Data {
					case "input":
						var name, value, inputType string
						for _, attr := range n.Attr {
							switch attr.Key {
							case "name":
								name = attr.Val
							case "value":
								value = attr.Val
							case "type":
								inputType = attr.Val
							}
						}
						if name != "" {
							if value == "" {
								switch inputType {
								case "checkbox", "radio":
									value = "on"
								default:
									value = "test"
								}
							}
							params = append(params, fmt.Sprintf("%s=%s", name, value))
						}

					case "select":
						var name string
						for _, attr := range n.Attr {
							if attr.Key == "name" {
								name = attr.Val
								break
							}
						}
						if name != "" {
							// 获取第一个option的值
							option := findFirstOption(n)
							if option != "" {
								params = append(params, fmt.Sprintf("%s=%s", name, option))
							}
						}

					case "textarea":
						var name string
						for _, attr := range n.Attr {
							if attr.Key == "name" {
								name = attr.Val
								break
							}
						}
						if name != "" {
							params = append(params, fmt.Sprintf("%s=test_textarea", name))
						}
					}
				}
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					f(c)
				}
			}
			f(n)

			if action != "" && len(params) > 0 {
				forms[action] = strings.Join(params, "&")
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			parseForm(c)
		}
	}
	parseForm(doc)
	return forms
}

func mergeDynamicParams(endpoints, forms map[string]string) string {
	var params []string

	for _, v := range endpoints {
		params = append(params, v)
	}
	for _, v := range forms {
		params = append(params, v)
	}

	return strings.Join(params, "&")
}

func buildRequestURL(params string) string {
	if len(params) > 200 { // 防止参数过长
		return "?" + params[:200]
	}
	return "?" + params
}
