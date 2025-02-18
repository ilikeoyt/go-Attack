package ConLoad

import (
	"log"
	"os"
)

var logFile *os.File // 将文件句柄保存为包级变量

func CreateErrorLog() *log.Logger {
	var err error
	logFile, err = os.OpenFile("error.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err) // 如果无法创建日志文件则终止程序
	}

	// 创建自定义logger（带时间戳和"ERROR:"前缀）
	errorLogger := log.New(logFile, "ERROR: ", log.LstdFlags)

	return errorLogger
}

// CloseLogFile 用于在程序退出时关闭日志文件
func CloseLogFile() {
	if logFile != nil {
		logFile.Close()
	}
}
