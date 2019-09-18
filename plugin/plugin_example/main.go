package main

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

var (
	runFlag uint32 = 0

	IndexPage = `<!DOCTYPE html>
<html>
<head>
<title>Hello World</title>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no">
<style>
</style>
</head>
<body>
	<h3>Hello World</h3>
</body>
</html>`
)

// return:
//        1) what domain?
//        2) is https?
//        3) is autocert?
//        4) is http redirect to https?
func VHostRegister() (string, bool, bool, bool) {
	if atomic.CompareAndSwapUint32(&runFlag, 0x0, 0x1) {
	}

	return "example.com", true, true, true
}

func VHostHandler(w http.ResponseWriter, r *http.Request) {
	// 写HTTP头
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// 写HTTP状态码
	w.WriteHeader(http.StatusOK)
	// 写页面
	fmt.Fprintf(w, IndexPage)
}

func main() {
}
