package main

import (
	"container/list"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"plugin"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/elitah/utils/autocert"
	"github.com/elitah/utils/logs"

	"github.com/inconshreveable/go-vhost"
	"github.com/panjf2000/ants"
)

type HTTPStat struct {
	s_http  uint64
	s_https uint64

	f_http  uint64
	f_https uint64
}

func (this *HTTPStat) AddAttach(https bool) {
	if https {
		this.s_https++
	} else {
		this.s_http++
	}
}

func (this *HTTPStat) AddFault(https bool) {
	if https {
		this.f_https++
	} else {
		this.f_http++
	}
}

func (this *HTTPStat) String() string {
	return fmt.Sprintf(`<td class="green">%d</td><td class="green">%d</td><td class="red">%d</td><td class="red">%d</td>`,
		this.s_http, this.s_https, this.f_http, this.f_https)
}

type HTTPRule struct {
	Plugin        bool
	PluginHandler func(w http.ResponseWriter, r *http.Request)

	AutoCert bool
	HTTPSUp  bool

	Target string
}

type HTTPSRule struct {
	Plugin        bool
	PluginHandler func(w http.ResponseWriter, r *http.Request)

	AutoCert bool

	Target string
}

type HostList struct {
	sync.RWMutex

	ListenHttpPort  int
	ListenHttpsPort int

	MasterDomain string

	mAntsPool *ants.Pool

	mList *list.List

	mListHTTP  map[string]*HTTPRule
	mListHTTPS map[string]*HTTPSRule

	mStat map[string]*HTTPStat

	mCC chan net.Conn

	mPool *sync.Pool

	mRegexpDomain   *regexp.Regexp
	mRegexpIPAddr   *regexp.Regexp
	mRegexpIPPort   *regexp.Regexp
	mRegexpHttpAuth *regexp.Regexp

	mClient *http.Client

	mAutoCert *autocert.AutoCertManager

	mSSLAddr net.Addr
}

func NewHostList(pool *ants.Pool) *HostList {
	jar, err := cookiejar.New(nil)

	if nil != err {
		logs.Warn(err)
	}

	return &HostList{
		ListenHttpPort:  80,
		ListenHttpsPort: 443,

		MasterDomain: "",

		mAntsPool: pool,

		mList: list.New(),

		mListHTTP:  make(map[string]*HTTPRule),
		mListHTTPS: make(map[string]*HTTPSRule),

		mStat: make(map[string]*HTTPStat),

		mCC: make(chan net.Conn),

		mPool: &sync.Pool{
			New: func() interface{} {
				return make([]byte, 32*1024)
			},
		},

		mRegexpDomain: regexp.MustCompile(`(\w+\.)+\w+`),
		mRegexpIPAddr: regexp.MustCompile(`(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)`),
		mRegexpIPPort: regexp.MustCompile(`^(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d):([0-9]|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{4}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$`),

		mClient: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Jar: jar,
		},

		mAutoCert: autocert.NewAutoCertManager(),
	}
}

func (this *HostList) LoadConfig(path string) bool {
	if "" == path {
		if file, err := exec.LookPath(os.Args[0]); nil == err {
			if _path, err := filepath.Abs(file); nil == err {
				if _path := filepath.Dir(_path); "" != _path {
					path = _path + "/config.json"
				}
			}
		}
	}

	if "" != path {
		if content, err := ioutil.ReadFile(path); nil == err {
			type rule struct {
				HttpTo  string `json:"http_to"`
				HttpsTo string `json:"https_to"`
			}
			list := &struct {
				HTTP     int              `json:"http"`
				HTTPS    int              `json:"https"`
				Domain   string           `json:"domain"`
				Username string           `json:"username"`
				Password string           `json:"password"`
				List     map[string]*rule `json:"list"`
			}{}
			if err := json.Unmarshal(content, list); nil == err {
				// 用于统计域名，方便排序
				var domains []string
				// 读取参数
				if 0 < list.HTTP && 65536 > list.HTTP {
					this.ListenHttpPort = list.HTTP
				}
				if 0 < list.HTTPS && 65536 > list.HTTPS {
					this.ListenHttpsPort = list.HTTPS
				}
				if "" != list.Domain {
					if nil != this.mRegexpDomain && this.mRegexpDomain.MatchString(list.Domain) {
						// 赋值主域名
						this.MasterDomain = list.Domain
						// 存入列表
						this.mListHTTP[list.Domain] = &HTTPRule{
							AutoCert: true,
						}
						// 存入列表
						this.mListHTTPS[list.Domain] = &HTTPSRule{
							AutoCert: true,
						}
					}
				}
				if "" != list.Username && "" != list.Password {
					this.mRegexpHttpAuth = regexp.MustCompile(fmt.Sprintf(`^(B|b)asic\s+%s$`,
						base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", list.Username, list.Password)))))
				}
				// 先统计域名
				for key, _ := range list.List {
					if "*" != key {
						domains = append(domains, key)
					}
				}
				// 排序
				sort.Strings(domains)
				// 添加全局
				domains = append(domains, "*")
				// 遍历列表并添加规则
				for _, domain := range domains {
					if rule, ok := list.List[domain]; ok {
						if "" != rule.HttpTo {
							if this.AddHTTP(domain, rule.HttpTo) {
								logs.Info("AddHTTP: %s => %s Success", domain, rule.HttpTo)
							} else {
								logs.Warn("AddHTTP: %s XX %s Failed", domain, rule.HttpTo)
							}
						}
						if "" != rule.HttpsTo {
							if this.AddHTTPS(domain, rule.HttpsTo) {
								logs.Info("AddHTTPS: %s => %s Success", domain, rule.HttpsTo)
							} else {
								logs.Warn("AddHTTPS: %s XX %s Failed", domain, rule.HttpsTo)
							}
						}
					}
				}
				return true
			} else {
				logs.Warn("Config: parse json failed,", err)
			}
		}
	}

	return false
}

func (this *HostList) LoadPlugin(fullpath string) string {
	var tmppath string

	// 创建临时文件
	if tmpfile, err := ioutil.TempFile("", fmt.Sprintf("plugin.so.%v.", time.Now().Unix())); nil == err {
		// 退出时删除
		defer os.Remove(tmpfile.Name())
		// 复制文件
		if content, err := ioutil.ReadFile(fullpath); nil == err {
			if n, err := tmpfile.Write(content); nil == err {
				if 0 < n {
					tmppath = tmpfile.Name()
				} else {
					logs.Warn("File empty copy")
				}
			} else {
				logs.Warn(err)
			}
		} else {
			logs.Warn(err)
		}
	} else {
		logs.Warn(err)
	}

	if "" != tmppath {
		if p, err := plugin.Open(tmppath); nil == err {
			if h1, err := p.Lookup("VHostRegister"); nil == err {
				if h2, err := p.Lookup("VHostHandler"); nil == err {
					if VHostRegister, ok := h1.(func() (string, bool, bool, bool)); ok {
						if VHostHandler, ok := h2.(func(w http.ResponseWriter, r *http.Request)); ok {
							if domain, https, autocert, http_up := VHostRegister(); "" != domain {
								if this.AddPlugin(domain, https, autocert, http_up, VHostHandler) {
									return domain
								} else {
									logs.Warn("Call AddPlugin return failed")
								}
							} else {
								logs.Warn("Unable call VHostRegister")
							}
						} else {
							logs.Warn("Unable get VHostHandler")
						}
					} else {
						logs.Warn("Unable get VHostRegister")
					}
				} else {
					logs.Warn(err)
				}
			} else {
				logs.Warn(err)
			}
		} else {
			logs.Warn(err)
		}
	}

	return ""
}

func (this *HostList) AddHTTP(domain, target string) bool {
	if "" != domain && "" != target {
		// 标记
		var autocert, https_up bool
		// 正则测试
		if "*" != domain && nil != this.mRegexpDomain {
			if !this.mRegexpDomain.MatchString(domain) {
				return false
			}
		}
		// 检查是否是自动证书模式
		if 11 < len(target) && strings.HasPrefix(target, "autocert://") {
			// 去除头
			target = target[11:len(target)]
			// 标记
			autocert = true
			// 检查是否是强制跳转HTTPS模式
		} else if 8 < len(target) && strings.HasPrefix(target, "https://") {
			// 标记
			https_up = true
			// 正则测试
			if nil != this.mRegexpDomain {
				if !this.mRegexpDomain.MatchString(target[8:len(target)]) {
					return false
				}
			}
		}
		// 如果不是强制跳转HTTPS，检查目标是否为ip:port形式
		if !https_up {
			// 正则测试
			if nil != this.mRegexpIPPort {
				if !this.mRegexpIPPort.MatchString(target) {
					return false
				}
			}
		}
		if _, ok := this.mListHTTP[domain]; !ok {
			var rule *HTTPRule
			// 根据不同模式创建规则
			if autocert {
				if _, ok := this.mListHTTPS[domain]; !ok {
					this.mListHTTPS[domain] = &HTTPSRule{
						AutoCert: autocert,
						Target:   target,
					}
					rule = &HTTPRule{
						AutoCert: autocert,
					}
				}
			} else {
				rule = &HTTPRule{
					HTTPSUp: https_up,
				}
			}
			if nil != rule {
				rule.Target = target
				this.mListHTTP[domain] = rule
				return true
			}
		}
	}
	return false
}

func (this *HostList) AddHTTPS(domain, target string) bool {
	if "" != domain && "" != target {
		if "*" != domain && nil != this.mRegexpDomain {
			if !this.mRegexpDomain.MatchString(domain) {
				return false
			}
		}
		if nil != this.mRegexpIPPort {
			if !this.mRegexpIPPort.MatchString(target) {
				return false
			}
		}
		if _, ok := this.mListHTTPS[domain]; !ok {
			this.mListHTTPS[domain] = &HTTPSRule{
				Target: target,
			}
			return true
		}
	}
	return false
}

func (this *HostList) AddPlugin(domain string, https, autocert, http_up bool, fn func(w http.ResponseWriter, r *http.Request)) bool {
	if "" != domain && nil != fn {
		if nil != this.mRegexpDomain {
			if !this.mRegexpDomain.MatchString(domain) {
				return false
			}
		}
		if https {
			if autocert {
				http_up = true
			}
			if http_up {
				this.mListHTTP[domain] = &HTTPRule{
					AutoCert: autocert,
					HTTPSUp:  http_up,

					Target: "https://" + domain,
				}
			}
			this.mListHTTPS[domain] = &HTTPSRule{
				Plugin:        true,
				PluginHandler: fn,

				AutoCert: autocert,
			}
		} else {
			this.mListHTTP[domain] = &HTTPRule{
				Plugin:        true,
				PluginHandler: fn,
			}
		}
		return true
	}
	return false
}

func (this *HostList) AddAttach(domain string, https ...bool) {
	this.Lock()

	if s, ok := this.mStat[domain]; ok {
		s.AddAttach(0 < len(https) && https[0])
	} else {
		s = &HTTPStat{}
		if 0 < len(https) && https[0] {
			s.s_https = 1
		} else {
			s.s_http = 1
		}
		this.mStat[domain] = s
	}

	this.Unlock()
}

func (this *HostList) AddFault(domain string, https ...bool) {
	this.Lock()

	if s, ok := this.mStat[domain]; ok {
		s.AddFault(0 < len(https) && https[0])
	} else {
		s = &HTTPStat{}
		if 0 < len(https) && https[0] {
			s.f_https = 1
		} else {
			s.f_http = 1
		}
		this.mStat[domain] = s
	}

	this.Unlock()
}

func (this *HostList) AddViewStatistics(domain string) {
	if "" != domain {
		this.Lock()

		if 32 < this.mList.Len() {
			this.mList.Back().Value = domain
			this.mList.MoveToFront(this.mList.Back())
		} else {
			this.mList.PushFront(domain)
		}

		this.Unlock()
	}
}

func (this *HostList) SetSSLAddr(addr net.Addr) {
	this.mSSLAddr = addr
}

func (this *HostList) TLSConfig() *tls.Config {
	return this.mAutoCert.TLSConfig()
}

func (this *HostList) Accept() (net.Conn, error) {
	if conn, ok := <-this.mCC; ok {
		return conn, nil
	}
	return nil, syscall.ENETDOWN
}

func (this *HostList) Addr() net.Addr {
	return this.mSSLAddr
}

func (this *HostList) Close() error {
	close(this.mCC)
	return nil
}

// https2http代理
func (this *HostList) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if nil != r.TLS {
		if this.MasterDomain == r.Host {
			this.ServeMaster(w, r)
			return
		} else if rule, _ := this.mListHTTPS[r.Host]; nil != rule {
			if rule.Plugin {
				rule.PluginHandler(w, r)
				// 退出
				return
			} else if rule.AutoCert {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if newReq := r.WithContext(ctx); nil != newReq {
					newReq.URL.Scheme = "http"
					newReq.URL.Host = rule.Target
					newReq.RequestURI = ""
					newReq.TLS = nil
					if resp, err := this.mClient.Do(newReq); nil == err {
						// 回写http头
						for key, value := range resp.Header {
							for _, v := range value {
								w.Header().Add(key, v)
							}
						}
						// 回写HTTP状态
						w.WriteHeader(resp.StatusCode)
						// 回写body
						io.Copy(w, resp.Body)
						// 关闭body
						resp.Body.Close()
						// 退出
						return
					} else {
						// 输出错误
						logs.Warn(err)
						// HTTP响应，转发请求失败
						this.HttpError(w, http.StatusBadGateway)
						// 退出
						return
					}
				}
			}
		} else {
			// HTTP响应，未找到
			this.HttpError(w, http.StatusNotFound)
			// 退出
			return
		}
	}
	// HTTP响应，内部服务错误
	this.HttpError(w, http.StatusInternalServerError)
}

func (this *HostList) ServeMaster(w http.ResponseWriter, r *http.Request) {
	if this.CheckHTTPAuth(w, r) {
		var n int

		this.RLock()
		n = len(this.mStat)
		this.RUnlock()

		if 0 < n {
			var i int

			list := make([]string, 0, n)

			fmt.Fprint(w, `<html>`)

			fmt.Fprint(w, `<head>`)
			fmt.Fprint(w, `<meta charset="UTF-8">`)
			fmt.Fprint(w, `<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=0">`)
			fmt.Fprint(w, `<meta http-equiv="Cache-Control" content="no-cache" />`)
			fmt.Fprint(w, `<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">`)
			fmt.Fprint(w, `<style>`)
			fmt.Fprint(w, `td { text-align: center; }`)
			fmt.Fprint(w, `.domain { width: 50%; background-color: #F8F8F8; }`)
			fmt.Fprint(w, `.red { background-color: #FFB5B5; }`)
			fmt.Fprint(w, `.green { background-color: #CEFFCE; }`)
			fmt.Fprint(w, `</style>`)
			fmt.Fprint(w, `</head>`)

			this.RLock()

			fmt.Fprint(w, `<p>最近访问的域名列表: <select>`)

			for e := this.mList.Front(); nil != e; e = e.Next() {
				i++
				fmt.Fprintf(w, `<option>%d: %v</option>`, i, e.Value)
			}

			fmt.Fprint(w, `</select></p>`)

			this.RUnlock()

			fmt.Fprint(w, `<table border="1" style="width: 60%; border-collapse: collapse;">`)
			fmt.Fprint(w, `<tr>`)
			fmt.Fprint(w, `<th class="domain">域名</th>`)
			fmt.Fprint(w, `<th class="green">HTTP</th>`)
			fmt.Fprint(w, `<th class="green">HTTPS</th>`)
			fmt.Fprint(w, `<th class="red">HTTP</th>`)
			fmt.Fprint(w, `<th class="red">HTTPS</th>`)
			fmt.Fprint(w, `</tr>`)

			this.RLock()

			for key, _ := range this.mStat {
				list = append(list, key)
			}

			this.RUnlock()

			sort.Strings(list)

			this.RLock()

			for _, item := range list {
				if s, ok := this.mStat[item]; ok {
					fmt.Fprintf(w, `<tr><td class="domain">%s</td>%v</tr>`, item, s)
				}
			}

			this.RUnlock()

			fmt.Fprint(w, `</table>`)
			fmt.Fprint(w, `</html>`)
		}
	}
}

func (this *HostList) HandleConn(conn net.Conn, https bool) (bool, error) {
	if vconn, err := this.GetVHostConn(conn, https); nil == err {
		this.AddViewStatistics(vconn.Host())
		switch _vconn := vconn.(type) {
		case *vhost.HTTPConn:
			defer vconn.Close()
			return false, this.HandleConnHTTP(_vconn)
		case *vhost.TLSConn:
			if keep, err := this.HandleConnHTTPS(_vconn, conn); nil == err {
				if !keep {
					vconn.Close()
				}
				return keep, nil
			} else {
				vconn.Close()
				return false, err
			}
		}
		vconn.Close()
		return false, syscall.EFAULT
	} else {
		return false, err
	}
}

func (this *HostList) HandleConnHTTP(src *vhost.HTTPConn) error {
	if nil != src {
		if key := this.TestDoman(src.Host()); "" != key {
			var rule *HTTPRule

			if rule = this.mListHTTP[key]; nil == rule {
				if rule = this.mListHTTP["*"]; nil != rule {
					key = fmt.Sprintf("*(%s)", key)
				}
			}

			if nil != rule {
				this.AddAttach(key, false)

				if rule.AutoCert {
					// 提交到自动证书模块
					this.mAutoCert.ServeRequest(src, src.Request)
				} else if rule.HTTPSUp {
					// HTTP 转 HTTPS
					this.HttpRedirect(src, rule.Target+src.Request.URL.RequestURI())
				} else if rule.Plugin {
					// 插件模式
					w := autocert.NewRedirectWriter()
					rule.PluginHandler(w, src.Request)
					w.Flush(src)
				} else {
					// TCP透传
					this.HandleConnGo(src, rule.Target)
				}

				return nil
			}

			if "" != key {
				this.AddFault(key, false)
			}
		}

		this.HttpError(src, http.StatusNotFound)

		return syscall.EFAULT
	}

	return syscall.EINVAL
}

func (this *HostList) HandleConnHTTPS(src *vhost.TLSConn, raw net.Conn) (bool, error) {
	if nil != src {
		if "" != src.Host() {
			if key := this.TestDoman(src.Host()); "" != key {
				var rule *HTTPSRule

				if rule = this.mListHTTPS[key]; nil == rule {
					if rule = this.mListHTTPS["*"]; nil != rule {
						key = fmt.Sprintf("*(%s)", key)
					}
				}

				if nil != rule {
					this.AddAttach(key, true)

					if rule.AutoCert {
						// 提交到HTTPS转发模块
						// 配置TCP KeepAlive
						if tcpConn, ok := raw.(*net.TCPConn); ok {
							tcpConn.SetKeepAlive(true)
							tcpConn.SetKeepAlivePeriod(3 * time.Minute)
						}

						// 通过channel传递到本地HTTPS服务器
						this.mCC <- src

						return true, nil
					} else {
						// TCP透传
						this.HandleConnGo(src, rule.Target)
					}

					return false, nil
				}

				if "" != key {
					this.AddFault(key, true)
				}
			}
		}

		return false, syscall.EFAULT
	}

	return false, syscall.EINVAL
}

func (this *HostList) HandleConnGo(src vhost.Conn, target string) {
	_, https := src.(*vhost.TLSConn)

	if dst, err := net.DialTimeout("tcp", target, 30*time.Second); nil == err {
		//logs.Info(src.RemoteAddr(), src.LocalAddr(), dst.RemoteAddr(), dst.LocalAddr())

		exit := make(chan byte)

		// 从客户端复制到服务端
		if err = this.mAntsPool.Submit(func() {
			this.Copy(dst, src)

			exit <- 1
		}); nil == err {
			// 从服务端复制到客户端
			this.Copy(src, dst)

			<-exit
		} else {
			src.Close()
			dst.Close()
		}

		close(exit)
	} else {
		logs.Warn("Dial: %v, HTTPS: %v, From %s => %s => %s", err, https, src.RemoteAddr(), src.LocalAddr(), target)

		this.HttpError(src, http.StatusGatewayTimeout)
	}
}

func (this *HostList) GetVHostConn(conn net.Conn, https bool) (vhost.Conn, error) {
	// 设置超时30秒
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	// 清空超时时间
	defer conn.SetReadDeadline(time.Time{})

	if !https {
		// 读取HTTP请求
		if vconn, err := vhost.HTTP(conn); nil == err {
			return vconn, nil
		} else {
			return nil, err
		}
	} else {
		// 读取HTTPS请求
		if vconn, err := vhost.TLS(conn); nil == err {
			return vconn, nil
		} else {
			return nil, err
		}
	}
}

func (this *HostList) CheckHTTPAuth(w http.ResponseWriter, r *http.Request) bool {
	if nil == this.mRegexpHttpAuth {
		return true
	}

	if nil != r && this.mRegexpHttpAuth.MatchString(r.Header.Get("Authorization")) {
		return true
	}

	if nil != w {
		w.Header().Set("WWW-Authenticate", `Basic realm="Need authorization!"`)
		w.WriteHeader(http.StatusUnauthorized)
	}

	return false
}

func (this *HostList) TestDoman(domain string) string {
	if "" != domain {
		if nil != this.mRegexpIPAddr {
			if this.mRegexpIPAddr.MatchString(domain) {
				return ""
			}
		}
		if nil != this.mRegexpIPPort {
			if this.mRegexpIPPort.MatchString(domain) {
				return ""
			}
		}
	}
	return domain
}

func (this *HostList) Copy(dst io.WriteCloser, src io.ReadCloser) (written int64, err error) {
	defer src.Close()
	defer dst.Close()

	if wt, ok := src.(io.WriterTo); ok {
		return wt.WriteTo(dst)
	}

	if rt, ok := dst.(io.ReaderFrom); ok {
		return rt.ReadFrom(src)
	}

	buf := this.mPool.Get().([]byte)
	defer this.mPool.Put(buf)

	for {
		nr, er := src.Read(buf)
		if 0 < nr {
			nw, ew := dst.Write(buf[:nr])
			if 0 < nw {
				written += int64(nw)
			}
			if nil != ew {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if io.EOF == er {
			break
		}
		if nil != er {
			err = er
			break
		}
	}

	return written, err
}

func (this *HostList) HttpError(w io.Writer, code int) {
	if http.StatusContinue <= code {
		httpStatus := http.StatusText(code)

		if _w, ok := w.(http.ResponseWriter); ok {
			// 输出HTTP头
			_w.WriteHeader(code)
			// 输出HTTP状态
			if "" != httpStatus {
				fmt.Fprint(w, httpStatus)
			}
			return
		}

		if "" != httpStatus {
			fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n", code, httpStatus)
			fmt.Fprintf(w, "Date: %s\r\n", time.Now().Format(time.RFC1123))
			fmt.Fprintf(w, "Content-Length: %d\r\n", len(httpStatus))
			fmt.Fprint(w, "Content-Type: text/plain; charset=utf-8\r\n\r\n")
			fmt.Fprint(w, httpStatus)
		}
	}
}

func (this *HostList) HttpRedirect(w io.Writer, location string) {
	if _w, ok := w.(http.ResponseWriter); ok {
		_w.Header().Set("Location", location)
		_w.WriteHeader(http.StatusFound)
		return
	}

	httpStatus := http.StatusText(http.StatusFound)

	if "" != httpStatus {
		fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n", http.StatusFound, httpStatus)
		fmt.Fprintf(w, "Date: %s\r\n", time.Now().Format(time.RFC1123))
		fmt.Fprintf(w, "Location: %s\r\n\r\n", location)
	}
}

func panicError(args ...interface{}) {
	if 0 < len(args) {
		for i, _ := range args {
			if nil == args[i] {
				return
			}
		}

		fmt.Println(args...)

		if "windows" == runtime.GOOS {
			time.Sleep(3 * time.Second)
		}

		os.Exit(0)

		select {}
	}
}

func main() {
	var portHttp, portHttps int = 80, 443

	logs.SetLogger(logs.AdapterConsole, `{"level":99,"color":true}`)
	logs.EnableFuncCallDepth(true)
	logs.SetLogFuncCallDepth(3)
	logs.Async()

	defer logs.Close()

	p, err := ants.NewPool(10000)

	panicError("无法创建协程池", err)

	defer p.Release()

	hostList := NewHostList(p)

	hostList.LoadConfig("")

	// 创建http监听
	l_http, err := net.Listen("tcp", fmt.Sprintf(":%d", portHttp))

	if nil != err {
		logs.Warn("Listen: %v, port: %d", err, portHttp)

		return
	}

	// 创建https监听
	l_https, err := net.Listen("tcp", fmt.Sprintf(":%d", portHttps))

	if nil != err {
		logs.Warn("Listen: %v, port: %d", err, portHttps)

		return
	}

	logs.Info("--------------------------------------------------------")

	if file, err := exec.LookPath(os.Args[0]); nil == err {
		if path, err := filepath.Abs(file); nil == err {
			if path := filepath.Dir(path); "" != path {
				// 正则
				if re := regexp.MustCompile(`^plugin_\w+\.so$`); nil != re {
					// 初始化插件
					if files, err := ioutil.ReadDir(path); nil == err {
						// 遍历文件
						for _, info := range files {
							if info.Mode().IsRegular() {
								basename := info.Name()
								if re.MatchString(basename) {
									if domain := hostList.LoadPlugin(filepath.Join(path, basename)); "" != domain {
										logs.Info("LoadPlugin: %s => %s Success", domain, basename)
									} else {
										logs.Warn("LoadPlugin: %s Failed", basename)
									}
								}
							}
						}
					} else {
						logs.Warn(err)
					}
				}
			}
		}
	}

	logs.Info("--------------------------------------------------------")

	// autocert代理
	// 监听hostList中的channel连接
	// 连接由https监听端转入
	p.Submit(func() {
		srv := http.Server{
			Handler:   hostList,
			TLSConfig: hostList.TLSConfig(),
		}
		if err := srv.ServeTLS(hostList, "", ""); http.ErrServerClosed != err {
			logs.Warn("AutoCert: %v\n", err)
		}
		srv.Close()
	})

	// 监听https
	// 对于autocert地址，将自动转入autocert代理
	p.Submit(func() {
		if l, ok := l_https.(*net.TCPListener); ok {
			hostList.SetSSLAddr(l.Addr())

			for {
				if conn, err := l.AcceptTCP(); nil == err {
					if err := p.Submit(func() {
						var keep bool
						if _keep, err := hostList.HandleConn(conn, true); nil == err {
							keep = _keep
						} else {
							logs.Warn("HandleConnHTTPS: %v, port: %d", err, portHttp)
						}
						if !keep {
							conn.Close()
						}
					}); nil != err {
						conn.Close()
						logs.Warn("ants.Submit:", err)
					}
				} else {
					logs.Warn("Accept: %v, port: %d", err, portHttps)
					break
				}
			}
		}
	})

	// 监听http
	p.Submit(func() {
		for {
			if conn, err := l_http.Accept(); nil == err {
				if err := p.Submit(func() {
					if _, err := hostList.HandleConn(conn, false); nil != err {
						logs.Warn("HandleConnHTTP: %v, port: %d", err, portHttp)
					}
					conn.Close()
				}); nil != err {
					conn.Close()
					logs.Warn("ants.Submit:", err)
				}
			} else {
				logs.Warn("Accept: %v, port: %d", err, portHttp)
				break
			}
		}
	})

	c_signal := make(chan os.Signal, 1)

	signal.Notify(c_signal, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

	ticker := time.NewTicker(3 * time.Second)

BREAK:
	for {
		select {
		case <-c_signal:
			break BREAK
		case <-ticker.C:
		}
	}

	p.Submit(func() {
		time.Sleep(3 * time.Second)
		os.Exit(-1)
	})

	l_https.Close()
	l_http.Close()
}
