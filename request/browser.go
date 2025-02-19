package request

import (
	"context"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"log"
	"time"
)

type Browser struct {
	ctx    context.Context
	cancel context.CancelFunc
}

func NewBrowser() (*Browser, error) {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.Flag("headless", true),
		chromedp.Flag("disable-gpu", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("ignore-certificate-errors", true),
	)

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))

	return &Browser{
		ctx:    ctx,
		cancel: cancel,
	}, nil
}

func (b *Browser) RenderFullDOM(url string) (string, []NetworkRequest, error) {
	var domContent string
	var requests []NetworkRequest

	// 设置超时控制
	ctx, cancel := context.WithTimeout(b.ctx, 30*time.Second)
	defer cancel()

	// 存储请求 ID 到请求的映射
	requestIDToRequest := make(map[network.RequestID]*NetworkRequest)

	// 监听网络请求
	chromedp.ListenTarget(ctx, func(ev interface{}) {
		switch ev := ev.(type) {
		case *network.EventRequestWillBeSent:
			req := NetworkRequest{
				URL:     ev.Request.URL,
				Method:  ev.Request.Method,
				Headers: ev.Request.Headers,
			}
			requestIDToRequest[ev.RequestID] = &req
		case *network.EventRequestWillBeSentExtraInfo:
			if req, ok := requestIDToRequest[ev.RequestID]; ok {
				requests = append(requests, *req)
				delete(requestIDToRequest, ev.RequestID)
			}
		}
	})

	// 自定义等待条件：网络空闲+DOM稳定
	err := chromedp.Run(ctx,
		network.Enable(),
		chromedp.Navigate(url),

		// 等待至少一个XHR请求完成
		chromedp.WaitVisible(`body`, chromedp.ByQuery),
		chromedp.Sleep(2*time.Second), // 初始内容加载

		// 检测页面是否完全就绪
		chromedp.EvaluateAsDevTools(`
                new Promise((resolve) => {
                    let lastHeight = document.body.scrollHeight;
                    let checkCount = 0;
                    
                    const checkReady = () => {
                        // 检测是否有未完成的请求
                        if(window.activeRequests && window.activeRequests > 0) return;
                        
                        // 检测DOM是否稳定
                        const newHeight = document.body.scrollHeight;
                        if(newHeight !== lastHeight) {
                            lastHeight = newHeight;
                            checkCount = 0;
                            return;
                        }
                        
                        if(++checkCount >= 3) { // 连续3次检查稳定
                            resolve(true);
                            return;
                        }
                        setTimeout(checkReady, 300);
                    };
                    
                    // 监听fetch请求
                    const originalFetch = window.fetch;
                    window.activeRequests = 0;
                    
                    window.fetch = (...args) => {
                        window.activeRequests++;
                        return originalFetch(...args).finally(() => {
                            window.activeRequests--;
                        });
                    };
                    
                    checkReady();
                });
            `, nil),

		// 获取完整DOM
		chromedp.OuterHTML("html", &domContent),
	)

	return domContent, requests, err
}

type NetworkRequest struct {
	URL      string
	Method   string
	PostData string
	Headers  map[string]interface{}
}
