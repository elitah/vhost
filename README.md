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
目前不支持指定配置文件路径，请可执行程序目录下创建config.json，格式如下：
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
    "e1.example.com": {
      "http_to": "autocert://127.0.0.1:30080"
    },
    "e2.example.com": {
      "http_to": "https://ros.elitah.xyz"
    },
    "*": {
      "http_to": "127.0.0.1:30080",
      "https_to": "127.0.0.1:30443"
    }
  }
}
```
