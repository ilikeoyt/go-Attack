# go-Attack
## ForeWord

该项目仅用于记录最近所遇到的漏洞一个系统性武器化开发。如有建议，欢迎各位师傅提交issue！

## Code Structure

由于本工具是自己想法的简单实现，并未参考一些成熟的漏扫工具，所以代码结构可能稍显简单。

```
go-Attack
	->CVEs
		->AnyVulTemplate.go
	->main.go
```

对某些代码段进行一些解释，便于二开及push

#### main.go

cveFunctionMap：用于添加字符串与指定漏洞函数的映射

![image](https://github.com/user-attachments/assets/31b5a43f-f708-4cdd-98de-1f4bda943a2f)


支持的命令行参数

![image](https://github.com/user-attachments/assets/0a7cd257-8ce3-4fd0-9a62-dfd0b65a0d94)


-u参数下的多线程（-list同理）

![image](https://github.com/user-attachments/assets/1badd3dc-c195-4dc1-89e2-2caf6b316dc9)


#### AnyVulTemplate.go

直接在函数中发送相关请求并进行判断即可

![image](https://github.com/user-attachments/assets/e4f426b0-a62b-4f19-8433-ee0d33244eb3)


## Useage

`-show`：查看支持的漏洞编号

![image](https://github.com/user-attachments/assets/072d0606-b27f-4766-9fd4-f0639f7c81d8)


`-u`：指定要扫描的url

`-list`：指定要扫描的url文件

`-cve`：指定漏洞编号，只会对目标进行该种漏洞扫描

`-attack`：输出攻击信息，含相应payload

![image](https://github.com/user-attachments/assets/c6c37417-416a-408e-926f-07b1bea7f8cf)


`-cookie`：指定请求时的cookie

如有代理需求，请在proxyURL中修改代理ip

![image](https://github.com/user-attachments/assets/591485c4-68b5-46ac-bde1-0e009cd20cc2)

并在相关函数添加

```
Proxy:           http.ProxyURL(proxyURL()),
```

![image](https://github.com/user-attachments/assets/28a08e28-1d18-4e1e-a9c3-92dd3f227041)


由于多线程的原因，某些经由时间延时检测的漏洞函数可能会出现误报，可以采用`-cve`参数指定漏洞类型，精确判断

![image](https://github.com/user-attachments/assets/685be149-ccbf-40b8-a7df-f46ddc90a0f2)


