package main

import (
	"container/list"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
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

	"github.com/elitah/fast-io"
	"github.com/elitah/utils/autocert"
	"github.com/elitah/utils/exepath"
	"github.com/elitah/utils/hash"
	"github.com/elitah/utils/logs"
	"github.com/elitah/utils/random"

	"github.com/inconshreveable/go-vhost"
	"github.com/panjf2000/ants"
)

var (
	rootDir = exepath.GetExeDir()
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

type SuffixRule interface {
	ChkSuffix(string) bool
}

type HTTPRule struct {
	PluginHandler func(w http.ResponseWriter, r *http.Request)

	AutoCert bool
	HTTPSUp  bool

	Target string

	Suffix string
}

func (this *HTTPRule) ChkSuffix(key string) bool {
	if "" != this.Suffix {
		return strings.HasSuffix(key, this.Suffix)
	}
	return false
}

type HTTPSRule struct {
	PluginHandler func(w http.ResponseWriter, r *http.Request)

	AutoCert bool

	Redirect bool

	Target string

	Suffix string

	AuthBase64 string

	AnonymousDir []string
}

func (this *HTTPSRule) ChkSuffix(key string) bool {
	if "" != this.Suffix {
		return strings.HasSuffix(key, this.Suffix)
	}
	return false
}

type AuthNode struct {
	start int64
	end   int64
}

func (this *AuthNode) Available() bool {
	return 0 == this.start || (0 < this.end && this.end <= time.Now().Unix()) || (this.start+600) <= time.Now().Unix()
}

func (this *AuthNode) Success() bool {
	return 0 < this.end && this.end > time.Now().Unix()
}

type HostList struct {
	sync.RWMutex

	ListenHttpPort  int
	ListenHttpsPort int

	AcceptIP bool

	MasterDomain string

	mAntsPool *ants.Pool

	mList *list.List

	mListHTTP  map[string]*HTTPRule
	mListHTTPS map[string]*HTTPSRule

	mListSuffix []SuffixRule

	mStat map[string]*HTTPStat

	mCC chan net.Conn

	mPool *sync.Pool

	mCookieSID      string
	mCookieValidity int

	mRegexpCookie *regexp.Regexp
	mRegexpDomain *regexp.Regexp
	mRegexpIPAddr *regexp.Regexp
	mRegexpIPPort *regexp.Regexp

	mHttpAuth string

	mClient *http.Client

	mAutoCert *autocert.AutoCertManager

	mSSLAddr net.Addr

	mReCAPTCHA       string
	mReCAPTCHAVerify string

	mGlobalCertFilepath string
	mGlobalKeyFilepath  string
	mGlobalCAFilepath  string

	mAuthCode map[string]*AuthNode
}

func NewHostList(pool *ants.Pool) *HostList {
	jar, err := cookiejar.New(nil)

	if nil != err {
		logs.Warn(err)
	} else {
		if nil != jar {
		}
	}

	return &HostList{
		ListenHttpPort:  80,
		ListenHttpsPort: 443,

		AcceptIP: false,

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

		mCookieSID:      random.NewRandomString(random.ModeNoLine, 16),
		mCookieValidity: 1800,

		mRegexpCookie: regexp.MustCompile(`^__auth_token_\d{10}__$`),
		mRegexpDomain: regexp.MustCompile(`(\w+\.)+\w+`),
		mRegexpIPAddr: regexp.MustCompile(`(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)`),
		mRegexpIPPort: regexp.MustCompile(`^(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d):([0-9]|[1-9]\d{1,3}|[1-5]\d{4}|6[0-4]\d{4}|65[0-4]\d{2}|655[0-2]\d|6553[0-5])$`),

		mClient: &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			//Jar: jar,
		},

		mAuthCode: make(map[string]*AuthNode),
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
				HttpTo       string   `json:"http_to"`
				HttpsTo      string   `json:"https_to"`
				AnonymousDir []string `json:"anonymous_dir"`
			}
			list := &struct {
				HTTP               int              `json:"http"`
				HTTPS              int              `json:"https"`
				AcceptIP           bool             `json:"accept_ip"`
				CookieValidity     int              `json:"cookie_validity"`
				ReCAPTCHA          string           `json:"recaptcha"`
				ReCAPTCHAVerify    string           `json:"recaptcha_verify"`
				GlobalCertFilepath string           `json:"global_cert_filepath"`
				GlobalKeyFilepath  string           `json:"global_key_filepath"`
				GlobalCAFilepath  string           `json:"global_ca_filepath"`
				Domain             string           `json:"domain"`
				Username           string           `json:"username"`
				Password           string           `json:"password"`
				Suffix             map[string]*rule `json:"suffix"`
				List               map[string]*rule `json:"list"`
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
				// 接受IP访问
				this.AcceptIP = list.AcceptIP
				// Cookie超时
				if this.mCookieValidity < list.CookieValidity {
					this.mCookieValidity = list.CookieValidity
				}
				// reCaptcha v3 api key
				if "" != list.ReCAPTCHA && "" != list.ReCAPTCHAVerify {
					this.mReCAPTCHA = list.ReCAPTCHA
					this.mReCAPTCHAVerify = list.ReCAPTCHAVerify
				}
				// cert chain
				if "" != list.GlobalCertFilepath && "" != list.GlobalKeyFilepath {
					this.mGlobalCertFilepath = list.GlobalCertFilepath
					this.mGlobalKeyFilepath = list.GlobalKeyFilepath
					this.mGlobalCAFilepath = list.GlobalCAFilepath
				}
				if "" != list.Domain {
					if nil != this.mRegexpDomain && this.mRegexpDomain.MatchString(list.Domain) {
						// 赋值主域名
						this.MasterDomain = list.Domain
						// 存入列表
						this.mListHTTP[list.Domain] = &HTTPRule{
							AutoCert: true,
							Target:   list.Domain,
						}
						// 存入列表
						this.mListHTTPS[list.Domain] = &HTTPSRule{
							AutoCert: true,
							Target:   list.Domain,
						}
					}
				}
				if "" != list.Username && "" != list.Password {
					this.mHttpAuth = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", list.Username, list.Password)))
				}
				// 先统计域名
				for key, _ := range list.Suffix {
					if "" != key && '.' == key[0] && 4 <= len(key) {
						domains = append(domains, key)
					}
				}
				for key, _ := range list.List {
					if "" != key && "*" != key && 3 <= len(key) {
						domains = append(domains, key)
					}
				}
				// 排序
				sort.Strings(domains)
				// 添加全局
				domains = append(domains, "*")
				// 遍历列表并添加规则
				for _, domain := range domains {
					var r *rule
					if '.' == domain[0] {
						if _r, ok := list.Suffix[domain]; ok {
							r = _r
						}
					}
					if nil == r {
						if _r, ok := list.List[domain]; ok {
							r = _r
						}
					}
					if nil != r {
						if "" != r.HttpTo {
							if this.AddHTTP(domain, r.HttpTo, r.AnonymousDir) {
								logs.Info("AddHTTP: %s => %s Success", domain, r.HttpTo)
							} else {
								logs.Warn("AddHTTP: %s XX %s Failed", domain, r.HttpTo)
							}
						}
						if "" != r.HttpsTo {
							if this.AddHTTPS(domain, r.HttpsTo) {
								logs.Info("AddHTTPS: %s => %s Success", domain, r.HttpsTo)
							} else {
								logs.Warn("AddHTTPS: %s XX %s Failed", domain, r.HttpsTo)
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

func (this *HostList) AddHTTP(domain, target string, anonymous_dir []string) bool {
	if "" != domain && "" != target {
		// 标记
		var autocert, https_up bool
		// 用户名和密码
		var username, password string
		// 正则测试
		if '.' != domain[0] && "*" != domain && nil != this.mRegexpDomain {
			if !this.mRegexpDomain.MatchString(domain) {
				return false
			}
		}
		// 检查是否是自动证书模式
		if 11 < len(target) && strings.HasPrefix(target, "autocert://") {
			if u, err := url.Parse(target); nil == err {
				// 获取用户名和密码
				if nil != u.User {
					username = u.User.Username()
					if _password, ok := u.User.Password(); ok {
						password = _password
					} else {
						password = username
					}
				}
				// 获取地址
				target = u.Host
				// 标记
				autocert = true
			} else {
				return false
			}
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
					if '.' == domain[0] {
						this.mListHTTPS[domain] = &HTTPSRule{
							AutoCert: autocert,
							Target:   target,
							Suffix:   domain,
						}
					} else {
						// 先创建
						_rule := &HTTPSRule{
							AutoCert: autocert,
							Target:   target,
						}
						// 填写用户名和密码
						if "" != username && "" != password {
							_rule.AuthBase64 = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
						}
						if 0 < len(anonymous_dir) {
							_rule.AnonymousDir = anonymous_dir
						}
						// 储存
						this.mListHTTPS[domain] = _rule
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
				if '.' == domain[0] {
					rule.Suffix = domain
					this.mListSuffix = append(this.mListSuffix, rule)
					return true
				}
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
		//
		autocert := strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://")
		//
		if !autocert {
			if nil != this.mRegexpIPPort {
				if !this.mRegexpIPPort.MatchString(target) {
					return false
				}
			}
		}
		if '.' == domain[0] {
			for _, _rule := range this.mListSuffix {
				if rule, ok := _rule.(*HTTPSRule); ok {
					if rule.Suffix == domain {
						rule.Target = target
						return true
					}
				}
			}
			this.mListSuffix = append(this.mListSuffix, &HTTPSRule{
				Target: target,
				Suffix: domain,
			})
			return true
		}
		if _, ok := this.mListHTTPS[domain]; !ok {
			this.mListHTTPS[domain] = &HTTPSRule{
				Target: target,

				AutoCert: autocert,
				Redirect: autocert,
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
				PluginHandler: fn,

				AutoCert: autocert,
			}
		} else {
			this.mListHTTP[domain] = &HTTPRule{
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

func (this *HostList) VerifyReCAPTCHA(token string, r *http.Request) bool {
	if "" != this.mReCAPTCHA {
		if "" != token {
			args := url.Values{}
			// 校验密钥
			args.Add("secret", this.mReCAPTCHAVerify)
			// 结果令牌
			args.Add("response", token)
			// 获取IP
			if address := strings.Split(r.RemoteAddr, ":"); 0 < len(address) {
				args.Add("remoteip", address[0])
			}
			// API查验
			if resp, err := http.PostForm("https://recaptcha.net/recaptcha/api/siteverify", args); nil == err {
				defer resp.Body.Close()
				//
				if http.StatusOK == resp.StatusCode {
					var buffer [1024]byte
					//
					if n, err := io.ReadFull(resp.Body, buffer[:]); nil == err || io.ErrUnexpectedEOF == err {
						if 0 < n {
							var result struct {
								Success     bool     `json:"success"`
								ChallengeTS string   `json:"challenge_ts"`
								Hostname    string   `json:"hostname"`
								Score       float32  `json:"score"`
								ErrorCodes  []string `json:"error-codes"`
							}
							//
							if err := json.Unmarshal(buffer[:n], &result); nil == err {
								if result.Success {
									if 0.6 <= result.Score {
										return true
									} else {
										logs.Error("result score: %f", result.Score)
									}
								} else {
									logs.Error("result success: false")
								}
							} else {
								logs.Error(err)
							}
						} else {
							logs.Error("read empty")
						}
					} else {
						logs.Error(err)
					}
				} else {
					logs.Error("http error: %d", resp.StatusCode)
				}
			} else {
				logs.Error(err)
			}
		}
		return false
	}
	return true
}

func (this *HostList) IsAuthLogin(w http.ResponseWriter, r *http.Request, domain string, rule *HTTPSRule) bool {
	if nil != w && nil != r && "" != domain && nil != rule {
		if "" != rule.AuthBase64 {
			for _, item := range rule.AnonymousDir {
				if strings.HasPrefix(r.URL.Path, item) {
					return true
				}
			}
			if list := r.Cookies(); 0 < len(list) {
				for _, item := range list {
					if this.mRegexpCookie.MatchString(item.Name) {
						if "" != item.Value {
							//
							hash.SetGobFormat(false)
							// 比对结果
							if hash.HashToString("sha1", rule.AuthBase64,
								item.Name[13:23],
								this.mCookieSID) == item.Value {
								// 修改有效期
								item.Path = "/"
								item.MaxAge = this.mCookieValidity
								item.HttpOnly = true
								// 更新cookie
								http.SetCookie(w, item)
								//
								return true
							}
						}
						// 修改有效期
						item.MaxAge = -1
						// 废除cookie
						http.SetCookie(w, item)
					}
				}
			}
		} else {
			return true
		}
	}
	return false
}

func (this *HostList) SetSSLAddr(addr net.Addr) {
	this.mSSLAddr = addr
}

func (this *HostList) TLSConfig() *tls.Config {
	if "" != this.mGlobalCertFilepath && "" != this.mGlobalKeyFilepath {
		if f, err := os.Open(this.mGlobalCertFilepath); nil == err {
			if path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd())); nil == err {
				this.mGlobalCertFilepath = path
			}
			f.Close()
		} else {
			this.mGlobalCertFilepath = filepath.Join(rootDir, filepath.Base(this.mGlobalCertFilepath))
		}
		if f, err := os.Open(this.mGlobalKeyFilepath); nil == err {
			if path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd())); nil == err {
				this.mGlobalKeyFilepath = path
			}
			f.Close()
		} else {
			this.mGlobalKeyFilepath = filepath.Join(rootDir, filepath.Base(this.mGlobalKeyFilepath))
		}
		if f, err := os.Open(this.mGlobalCAFilepath); nil == err {
			if path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", f.Fd())); nil == err {
				this.mGlobalCAFilepath = path
			}
			f.Close()
		} else {
			this.mGlobalCAFilepath = filepath.Join(rootDir, filepath.Base(this.mGlobalCAFilepath))
		}
		//
		logs.Info(this.mGlobalCertFilepath)
		logs.Info(this.mGlobalKeyFilepath)
		logs.Info(this.mGlobalCAFilepath)
		//
		if certPem, err := ioutil.ReadFile(this.mGlobalCertFilepath); nil == err {
			if keyPem, err := ioutil.ReadFile(this.mGlobalKeyFilepath); nil == err {
				if cert, err := tls.X509KeyPair(certPem, keyPem); nil == err {
					//
					if caPem, err := ioutil.ReadFile(this.mGlobalCAFilepath); nil == err {
						//
						pool := x509.NewCertPool()
						//
						pool.AppendCertsFromPEM(caPem)
						//
						return &tls.Config{
							Certificates: []tls.Certificate{cert},

							ClientCAs:  pool,
							ClientAuth: tls.RequireAndVerifyClientCert,
						}
					}
					//
					return &tls.Config{
						Certificates: []tls.Certificate{cert},
					}
				} else {
					logs.Error(err)
				}
			} else {
				logs.Error(err)
			}
		} else {
			logs.Error(err)
		}
	}
	if nil == this.mAutoCert {
		this.mAutoCert = autocert.NewAutoCertManager()
	}
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
			if nil != rule.PluginHandler {
				//
				rule.PluginHandler(w, r)
				// 退出
				return
			} else if rule.Redirect {
				//
				this.HttpRedirect(w, rule.Target)
				//
				return
			} else if rule.AutoCert {
				if !this.IsAuthLogin(w, r, r.Host, rule) {
					if "GET" == r.Method {
						if referer := r.Header.Get("Referer"); "" != referer {
							if u, err := url.Parse(referer); nil == err {
								if code := u.Query().Get("code"); "" != code {
									if this.CheckAuthCodeOK(code) {
										//
										timeunix := time.Now().Unix()
										//
										hash.SetGobFormat(false)
										//
										http.SetCookie(w, &http.Cookie{
											Name: fmt.Sprintf("__auth_token_%d__", timeunix),
											Value: hash.HashToString("sha1", rule.AuthBase64,
												timeunix,
												this.mCookieSID),
											MaxAge:   this.mCookieValidity,
											HttpOnly: true,
										})
										//
										this.HttpRedirect(w, r.URL.RequestURI())
										//
										return
									}
								}
							}
						}
						if "" != this.MasterDomain {
							//
							v := url.Values{}
							//
							v.Add("redirect", fmt.Sprintf("https://%s%s", r.Host, r.URL.RequestURI()))
							//
							u := url.URL{
								Scheme:   "https",
								Host:     this.MasterDomain,
								Path:     "/login",
								RawQuery: v.Encode(),
							}
							//
							this.HttpRedirect(w, u.String())
							//
							return
						}
					}
					//
					w.WriteHeader(http.StatusUnauthorized)
					//
					return
				}
				if hj, ok := w.(http.Hijacker); ok {
					// 得到原始连接
					if conn_remote, _, err := hj.Hijack(); nil == err {
						// 退出时关闭
						defer conn_remote.Close()
						// 连接目标
						if conn_local, err := net.DialTimeout("tcp", rule.Target, 30*time.Second); nil == err {
							// 退出时关闭
							defer conn_local.Close()
							// 修改请求
							r.URL.Scheme = "http"
							r.TLS = nil
							// 写请求
							r.Write(conn_local)
							//
							fast_io.FastCopy(conn_remote, conn_local)
							//
							return
						} else {
							// 输出错误
							logs.Warn(err)
						}
					} else {
						// 输出错误
						logs.Warn(err)
					}
				} else {
					// 输出错误
					logs.Warn("unable to hijack connection")
				}
			}
			// HTTP响应，转发请求失败
			this.HttpError(w, http.StatusBadGateway)
			// 退出
			return
		}
		// HTTP响应，未找到
		this.HttpError(w, http.StatusNotFound)
		// 退出
		return
	}
	// HTTP响应，内部服务错误
	this.HttpError(w, http.StatusInternalServerError)
}

func (this *HostList) ServeMaster(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/":
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
				fmt.Fprint(w, `<body>`)

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

				fmt.Fprint(w, `<table border="1" style="margin-top: 2em; width: 60%; border-collapse: collapse;">`)
				fmt.Fprint(w, `<tr>`)
				fmt.Fprint(w, `<th class="domain">域名</th>`)
				fmt.Fprint(w, `<th class="green">插件</th>`)
				fmt.Fprint(w, `<th class="green">自动证书</th>`)
				fmt.Fprint(w, `<th class="red">强制HTTPS</th>`)
				fmt.Fprint(w, `<th class="red">目标</th>`)
				fmt.Fprint(w, `</tr>`)

				if 0 < len(this.mListHTTP) {
					var list []string
					for domain, _ := range this.mListHTTP {
						if this.MasterDomain != domain {
							list = append(list, domain)
						}
					}
					sort.Strings(list)
					for _, item := range list {
						if rule, ok := this.mListHTTP[item]; ok {
							fmt.Fprint(w, `<tr>`)
							fmt.Fprintf(w, `<td>%s</td>`, item)
							fmt.Fprintf(w, `<td>%v</td>`, nil != rule.PluginHandler)
							fmt.Fprintf(w, `<td>%v</td>`, rule.AutoCert)
							fmt.Fprintf(w, `<td>%v</td>`, rule.HTTPSUp)
							fmt.Fprintf(w, `<td>%s</td>`, rule.Target)
							fmt.Fprint(w, `</tr>`)
						}
					}
				}

				fmt.Fprint(w, `</table>`)

				fmt.Fprint(w, `<table border="1" style="margin-top: 2em; width: 60%; border-collapse: collapse;">`)
				fmt.Fprint(w, `<tr>`)
				fmt.Fprint(w, `<th class="domain">域名</th>`)
				fmt.Fprint(w, `<th class="green">插件</th>`)
				fmt.Fprint(w, `<th class="green">自动证书</th>`)
				fmt.Fprint(w, `<th class="green">跳转</th>`)
				fmt.Fprint(w, `<th class="red">目标</th>`)
				fmt.Fprint(w, `<th class="red">密钥</th>`)
				fmt.Fprint(w, `</tr>`)

				if 0 < len(this.mListHTTPS) {
					var list []string
					//
					for domain, _ := range this.mListHTTPS {
						if this.MasterDomain != domain {
							list = append(list, domain)
						}
					}
					//
					sort.Strings(list)
					//
					for _, item := range list {
						if rule, ok := this.mListHTTPS[item]; ok {
							fmt.Fprint(w, `<tr>`)
							fmt.Fprintf(w, `<td>%s</td>`, item)
							fmt.Fprintf(w, `<td>%v</td>`, nil != rule.PluginHandler)
							fmt.Fprintf(w, `<td>%v</td>`, rule.AutoCert)
							fmt.Fprintf(w, `<td>%v</td>`, rule.Redirect)
							fmt.Fprintf(w, `<td>%s</td>`, rule.Target)
							//
							if "" != rule.AuthBase64 {
								if data, err := base64.StdEncoding.DecodeString(rule.AuthBase64); nil == err {
									fmt.Fprintf(w, `<td>%s</td>`, string(data))
								} else {
									fmt.Fprint(w, `<td></td>`)
								}
							} else {
								fmt.Fprint(w, `<td></td>`)
							}
							fmt.Fprint(w, `</tr>`)
						}
					}
				}

				fmt.Fprint(w, `</table>`)

				fmt.Fprint(w, `<table border="1" style="margin-top: 2em; width: 60%; border-collapse: collapse;">`)
				fmt.Fprint(w, `<tr>`)
				fmt.Fprint(w, `<th class="domain">域名</th>`)
				fmt.Fprint(w, `<th class="green">插件</th>`)
				fmt.Fprint(w, `<th class="green">自动证书</th>`)
				fmt.Fprint(w, `<th class="red">强制HTTPS</th>`)
				fmt.Fprint(w, `<th class="red">目标</th>`)
				fmt.Fprint(w, `<th class="red">前缀</th>`)
				fmt.Fprint(w, `<th class="red">密钥</th>`)
				fmt.Fprint(w, `</tr>`)

				for _, rule := range this.mListSuffix {
					fmt.Fprint(w, `<tr>`)
					if _rule, ok := rule.(*HTTPRule); ok {
						fmt.Fprintf(w, `<td>*%s</td>`, _rule.Suffix)
						fmt.Fprintf(w, `<td>%v</td>`, nil != _rule.PluginHandler)
						fmt.Fprintf(w, `<td>%v</td>`, _rule.AutoCert)
						fmt.Fprintf(w, `<td>%v</td>`, _rule.HTTPSUp)
						fmt.Fprintf(w, `<td>%s</td>`, _rule.Target)
						fmt.Fprintf(w, `<td>*%s</td>`, _rule.Suffix)
						fmt.Fprint(w, `<td></td>`)
					} else if _rule, ok := rule.(*HTTPSRule); ok {
						fmt.Fprintf(w, `<td>*%s</td>`, _rule.Suffix)
						fmt.Fprintf(w, `<td>%v</td>`, nil != _rule.PluginHandler)
						fmt.Fprintf(w, `<td>%v</td>`, _rule.AutoCert)
						fmt.Fprint(w, `<td></td>`)
						fmt.Fprintf(w, `<td>%s</td>`, _rule.Target)
						fmt.Fprintf(w, `<td>*%s</td>`, _rule.Suffix)
						//
						if "" != _rule.AuthBase64 {
							if data, err := base64.StdEncoding.DecodeString(_rule.AuthBase64); nil == err {
								fmt.Fprintf(w, `<td>%s</td>`, string(data))
							} else {
								fmt.Fprint(w, `<td></td>`)
							}
						} else {
							fmt.Fprint(w, `<td></td>`)
						}
					}
					fmt.Fprint(w, `</tr>`)
				}

				fmt.Fprint(w, `</table>`)

				fmt.Fprint(w, `</body>`)
				fmt.Fprint(w, `</html>`)
			}
		} else {
			//
			v := url.Values{}
			//
			v.Add("redirect", fmt.Sprintf("https://%s%s", r.Host, r.URL.RequestURI()))
			//
			u := url.URL{
				Scheme:   "https",
				Host:     r.Host,
				Path:     "/login",
				RawQuery: v.Encode(),
			}
			//
			this.HttpRedirect(w, u.String())
		}
		return
	case "/header":
		//
		fmt.Fprintf(w, "Method: %s\r\n", r.Method)
		//
		if nil != r.URL {
			fmt.Fprintf(w, "Method: %s\r\n", r.URL.String())
		}
		//
		fmt.Fprintf(w, "Proto: %s, %d, %d\r\n", r.Proto, r.ProtoMajor, r.ProtoMinor)
		//
		fmt.Fprintf(w, "ContentLength: %d\r\n", r.ContentLength)
		//
		fmt.Fprintf(w, "TransferEncoding: %s\r\n", strings.Join(r.TransferEncoding, ", "))
		//
		fmt.Fprintf(w, "Close: %v\r\n", r.Close)
		//
		fmt.Fprintf(w, "Host: %s\r\n", r.Host)
		//
		fmt.Fprintf(w, "Form: %v\r\n", r.Form)
		//
		fmt.Fprintf(w, "PostForm: %v\r\n", r.PostForm)
		//
		fmt.Fprintf(w, "RemoteAddr: %s\r\n", r.RemoteAddr)
		//
		fmt.Fprintf(w, "RequestURI: %s\r\n", r.RequestURI)
		//
		fmt.Fprint(w, "=== Trailer ==================================\r\n")
		//
		for key, value := range r.Trailer {
			fmt.Fprintf(w, "%s: %v\r\n", key, strings.Join(value, ", "))
		}
		//
		fmt.Fprint(w, "=== Header ==================================\r\n")
		//
		for key, value := range r.Header {
			fmt.Fprintf(w, "%s: %v\r\n", key, strings.Join(value, ", "))
		}
		//
		return
	case "/notice":
		if errno := r.URL.Query().Get("errno"); "" != errno {
			var errstr string
			//
			switch errno {
			case "1":
				errstr = "非法来源，请使用合法的浏览器访问此页"
			case "2":
				errstr = "参数错误"
			case "3":
				errstr = "找不到此对象"
			case "4":
				if redirect := r.URL.Query().Get("redirect"); "" != redirect {
					//
					v := url.Values{}
					//
					if code := r.URL.Query().Get("code"); "" != code {
						v.Set("code", code)
					}
					v.Set("redirect", redirect)
					//
					u := url.URL{
						Path:     "/login",
						RawQuery: v.Encode(),
					}
					errstr = fmt.Sprintf("用户名或密码错误，<a href=%s>返回</a>", u.String())
				} else {
					errstr = "参数错误"
				}
			}
			//
			fmt.Fprintf(w, `<html>
	<head>
		<meta charset="UTF-8">
		<title>错误</title>
		<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=0">
		<meta http-equiv="Cache-Control" content="no-cache" />
		<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
	</head>
	<body>
		<p>%s</p>
	</body>
</html>
`, errstr)
			return
		}
		this.HttpError(w, http.StatusBadRequest)
		return
	case "/login":
		if "GET" == r.Method {
			if redirect := r.URL.Query().Get("redirect"); "" != redirect {
				if u, err := url.Parse(redirect); nil == err {
					var code string
					//
					if this.MasterDomain != u.Host {
						code = r.FormValue("code")
					}
					if this.MasterDomain == u.Host || this.CheckAuthCode(code) {
						for i := 0; 1 > i; i++ {
							if this.MasterDomain == r.Host {
								break
							}
							if rule := this.mListHTTPS[u.Host]; nil != rule {
								// 判断是否已登录
								if !this.IsAuthLogin(w, r, u.Host, rule) {
									break
								}
							}
							this.HttpRedirect(w, redirect)
							return
						}
						fmt.Fprintf(w, `<html>
	<head>
		<meta charset="UTF-8">
		<title>登陆</title>
		<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=0">
		<meta http-equiv="Cache-Control" content="no-cache" />
		<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
		<script type="text/javascript">
		function validate_required(field, alerttxt) {
			with (field) {
				if (null == value || "" == value) {
					alert(alerttxt);
					return false;
				} else {
					return true;
				}
			}
			return false;
		}
		function validate_form(thisform) {
			with (thisform) {
				if (true != validate_required(username, "请输入用户名!")) {
					username.focus();
					return false
				}
				if (true != validate_required(password, "请输入密码!")) {
					password.focus();
					return false
				}
			}
			return true;
		}
		</script>
	</head>
	<body>
		<form action="/login" method="POST" onsubmit="return validate_form(this);">
			<p>
				<input type="hidden" id="recaptcha" name="recaptcha" />
				<input type="hidden" name="redirect" value="%s" />
				<input type="hidden" name="code" value="%s" />
			</p>
			<table>
				<tr>
					<td>用户名</td>
					<td><input type="text" name="username" /></td>
				</tr>
				<tr>
					<td>密码</td>
					<td><input type="password" name="password" /></td>
				</tr>
				<tr>
					<td></td>
					<td><input type="submit" id="submit" value="请稍候" disabled="disabled" /></td>
				</tr>
			</table>
		</form>
		`, redirect, code)
						if "" != this.mReCAPTCHA {
							fmt.Fprintf(w, `<script src="https://recaptcha.net/recaptcha/api.js?render=%s"></script>
		<script>
		grecaptcha.ready(function() {
			grecaptcha.execute('%s', {action: 'homepage'}).then(function(token) {
				var btn = document.getElementById("submit");
				if (btn) {
					btn.disabled = "";
					btn.value = "登陆";
				}
				document.getElementById("recaptcha").value = token;
			});
		});
		</script>
`, this.mReCAPTCHA, this.mReCAPTCHA)
						} else {
							fmt.Fprintf(w, `<script>
		var btn = document.getElementById("submit");
		if (btn) {
			btn.disabled = "";
			btn.value = "登陆";
		}
		</script>
	`)
						}
						fmt.Fprintf(w, `</body>
</html>
`)
						return
					} else {
						// 更新code
						if code = random.NewRandomString(random.ModeNoLine, 16); "" != code {
							//
							result := url.URL{
								Path: "/login",
							}
							//
							v := url.Values{}
							//
							v.Add("redirect", redirect)
							v.Add("code", code)
							//
							result.RawQuery = v.Encode()
							//
							this.HttpRedirect(w, result.String())
							//
							this.mAuthCode[code] = &AuthNode{
								start: time.Now().Unix(),
								end:   0,
							}
						} else {
							this.HttpError(w, http.StatusBadRequest)
						}
						return
					}
					this.HttpRedirect(w, redirect)
					return
				} else {
					logs.Warn(err)
				}
			}
			this.HttpError(w, http.StatusBadRequest)
			return
		} else if "POST" == r.Method {
			// 错误号
			var errno int = 0
			// 跳转地址
			var redirectCode string
			var redirectURL string
			// 机器识别
			if !this.VerifyReCAPTCHA(r.FormValue("recaptcha"), r) {
				// 恶意用户
				errno = 1
			} else {
				if redirect := r.FormValue("redirect"); "" != redirect {
					if u, err := url.Parse(redirect); nil == err {
						if this.MasterDomain != u.Host {
							redirectCode = r.FormValue("code")
						}
						if this.MasterDomain == u.Host || "" != redirectCode {
							var validKey string
							//
							redirectURL = redirect
							//
							if this.MasterDomain == u.Host {
								validKey = this.mHttpAuth
							} else if rule := this.mListHTTPS[u.Host]; nil != rule {
								validKey = rule.AuthBase64
							}
							if "" != validKey {
								//
								if username := r.FormValue("username"); "" != username {
									if password := r.FormValue("password"); "" != password {
										result := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))
										if result == validKey {
											if this.MasterDomain == u.Host {
												http.SetCookie(w, &http.Cookie{
													Name:     "__auth_token__",
													Value:    hash.HashToString("sha1", validKey, this.mCookieSID),
													MaxAge:   this.mCookieValidity,
													HttpOnly: true,
												})
											} else {
												//激活令牌
												this.SetAuthCodeConfirm(redirectCode)
											}
											//跳转
											this.HttpRedirect(w, redirect)
											//返回
											return
										} else {
											logs.Error("%s:%s => %s => %s", username, password, result, validKey)
										}
									} else {
										logs.Error("no password")
									}
								} else {
									logs.Error("no username")
								}
								// 用户名或密码错误
								errno = 4
							} else {
								// 找不到对象
								errno = 3
							}
						} else {
							errno = 2
						}
					} else {
						errno = 2
					}
				} else {
					errno = 2
				}
			}
			//
			v := url.Values{}
			//
			v.Set("errno", fmt.Sprint(errno))
			//
			if "" != redirectCode {
				v.Set("code", redirectCode)
			}
			//
			v.Set("redirect", redirectURL)
			//
			result := &url.URL{
				Path:     "/notice",
				RawQuery: v.Encode(),
			}
			//
			this.HttpRedirect(w, result.String())
			//
			return
		} else if "HEAD" == r.Method {
			return
		}
		this.HttpError(w, http.StatusMethodNotAllowed)
		return
	}
	this.HttpError(w, http.StatusNotFound)
}

func (this *HostList) HandleConn(conn net.Conn, https bool) (bool, error) {
	if vconn, err := this.GetVHostConn(conn, https); nil == err {
		this.AddViewStatistics(vconn.Host())
		//
		logs.Info("host: %s, https: %v", vconn.Host(), https)
		//
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
				for _, r := range this.mListSuffix {
					if r.ChkSuffix(key) {
						var ok bool
						rule, ok = r.(*HTTPRule)
						if ok {
							break
						}
					}
				}
				if nil == rule {
					if rule = this.mListHTTP["*"]; nil != rule {
						key = fmt.Sprintf("*(%s)", key)
					}
				}
			}

			if nil != rule {
				this.AddAttach(key, false)

				if rule.AutoCert {
					if nil != this.mAutoCert {
						// 提交到自动证书模块
						this.mAutoCert.ServeRequest(src, src.Request)
					} else {
						// HTTP 转 HTTPS
						this.HttpRedirect(src, fmt.Sprintf("https://%s%s", rule.Target, src.Request.URL.RequestURI()))
					}
				} else if rule.HTTPSUp {
					// HTTP 转 HTTPS
					this.HttpRedirect(src, rule.Target+src.Request.URL.RequestURI())
				} else if nil != rule.PluginHandler {
					// 创建输出器
					w := autocert.NewRedirectWriter()
					// 插件模式
					rule.PluginHandler(w, src.Request)
					// 输出结果
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
					for _, r := range this.mListSuffix {
						if r.ChkSuffix(key) {
							var ok bool
							rule, ok = r.(*HTTPSRule)
							if ok {
								break
							}
						}
					}
					if nil == rule {
						if rule = this.mListHTTPS["*"]; nil != rule {
							key = fmt.Sprintf("*(%s)", key)
						}
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
	if dst, err := net.DialTimeout("tcp", target, 30*time.Second); nil == err {
		fast_io.FastCopy(src, dst)
	} else {
		_, https := src.(*vhost.TLSConn)

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

func (this *HostList) CheckAuthCode(code string) bool {
	if _, ok := this.mAuthCode[code]; ok {
		return true
	}
	return false
}

func (this *HostList) CheckAuthCodeOK(code string) bool {
	if node, ok := this.mAuthCode[code]; ok {
		defer func() {
			//
			delete(this.mAuthCode, code)
			//
			for key, value := range this.mAuthCode {
				if !value.Available() {
					delete(this.mAuthCode, key)
				}
			}
		}()
		//
		return node.Success()
	}
	return false
}

func (this *HostList) SetAuthCodeConfirm(code string) {
	if n, ok := this.mAuthCode[code]; ok {
		n.end = time.Now().Unix() + 180
	}
}

func (this *HostList) CheckHTTPAuth(w http.ResponseWriter, r *http.Request) bool {
	if "" == this.mHttpAuth {
		return true
	}

	if cookie, err := r.Cookie("__auth_token__"); nil == err {
		if hash.HashToString("sha1", this.mHttpAuth, this.mCookieSID) == cookie.Value {
			//
			cookie.Path = "/"
			cookie.MaxAge = this.mCookieValidity
			cookie.HttpOnly = true
			// 更新cookie
			http.SetCookie(w, cookie)
			//
			return true
		}
	}

	/*
		if nil != r && this.mRegexpHttpAuth.MatchString(r.Header.Get("Authorization")) {
			return true
		}

		if nil != w {
			w.Header().Set("WWW-Authenticate", `Basic realm="Need authorization!"`)
			w.WriteHeader(http.StatusUnauthorized)
		}
	*/

	return false
}

func (this *HostList) TestDoman(domain string) string {
	if "" != domain {
		if nil != this.mRegexpIPAddr {
			if this.mRegexpIPAddr.MatchString(domain) {
				if this.AcceptIP {
					return "*"
				} else {
					return ""
				}
			}
		}
		if nil != this.mRegexpIPPort {
			if this.mRegexpIPPort.MatchString(domain) {
				//
				domain, _, _ = net.SplitHostPort(domain)
				//
				return domain
			}
		}
		if _domain := strings.SplitN(domain, ":", 2); 2 <= len(_domain) {
			return _domain[0]
		}
	}
	return domain
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

	if 0 < hostList.ListenHttpPort && portHttp != hostList.ListenHttpPort {
		portHttp = hostList.ListenHttpPort
	}

	if 0 < hostList.ListenHttpsPort && portHttps != hostList.ListenHttpsPort {
		portHttps = hostList.ListenHttpsPort
	}

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
