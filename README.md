vhost
---
vhost(write by golang)



如何使用
---
安装golang编译器，make工具

直接执行make即可



运行环境
---
目前仅测试Centos 7 x64



配置文件
---
目前不支持指定配置文件路径，请可执行程序目录下创建config.json，以下为参考配置：

规则如下：
- 当用户访问`http://example.com`跳转到`https://example.com`，模式为直接HTTP 302跳转
- 当用户访问`https://example.com`将启动TCP透传模式，将数据发送到127.0.0.1:18880，需要自行提供证书
- 当用户访问`http://www.example.com`跳转到`https://example.com`，模式为直接HTTP 302跳转
- 当用户访问`http://autocert.example.com`跳转到`https://autocert.example.com`，模式为直接HTTP 302跳转
- 当用户访问`https://autocert.example.com`将启动反向代理模式，自动申请证书，将HTTP页面升级到HTTPS
- 未指定的域名将匹配`*`规则

参数配置文件：
config.json
```
{
  "http": 80,
  "https": 443,
  "domain": "统计页面入口域名，此域名不会转发",
  "username": "统计页面授权用户名",
  "password": "统计页面授权用户密码",
  "list": {
    "example.com": {
      "http_to": "https://example.com",
      "https_to": "127.0.0.1:18880"
    },
    "www.example.com": {
      "http_to": "https://example.com"
    },
    "autocert.example.com": {
      "http_to": "autocert://127.0.0.1:30080"
    },
    "*": {
      "http_to": "127.0.0.1:30080",
      "https_to": "127.0.0.1:30443"
    }
  }
}
```
