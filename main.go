package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	versionString = "$Rev$"
)

var Tag = "Tiny Proxy"
var host = ""
var global = struct {
	AllowAnonymous          bool
	NoCaching               bool // Only for plain HTTP proxy. CONNECT proxy connections are untouched and won't affected by this parameter
	UseProxyFromEnvironment bool
	UpstreamDialTimeout     time.Duration // Dial timeout for upstream dial (including dns resolve and connect), default to 30 seconds. net.Dialer.Timeout
}{
	AllowAnonymous:          false,
	NoCaching:               false,
	UseProxyFromEnvironment: false,
	UpstreamDialTimeout:     30 * time.Second, // usually used to close conection earlier for dumb or blocked address
}

var tr = &http.Transport{
	Proxy: func() func(*http.Request) (*url.URL, error) {
		if global.UseProxyFromEnvironment {
			return http.ProxyFromEnvironment
		} else {
			return nil
		}
	}(),
	Dial: func(network, addr string) (net.Conn, error) {
		return net.DialTimeout(network, addr, global.UpstreamDialTimeout)
	},
}

type SmartProxy struct {
	counter   uint64
	connected int64
}

type User struct {
	Username string
	Password string
}

func (u *User) Authenticated() bool {
	if u.Username == "" {
		return false
	} else {
		switch u.Username {
		case "invalid":
			return false
		case "nsclub":
			return u.Password == "nsclub"
		default:
		}
	}
	return true
}

func (u *User) Authorized() bool {
	return true && u.Authenticated()
}

type ProxyContext struct {
	counter uint64
	*User
	*log.Logger
}

func (s *SmartProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := &ProxyContext{atomic.AddUint64(&s.counter, 1), nil, log.New(os.Stderr, "", 0)}
	ctx.SetPrefix(fmt.Sprintf("[Core][%d/%d][%v][%v] ", ctx.counter, s.connected, r.RemoteAddr, r.Host))
	ctx.Println(r.Method, r.RequestURI)

	atomic.AddInt64(&s.connected, 1)
	defer func() {
		atomic.AddInt64(&s.connected, -1)
	}()

	authStr := r.Header["Proxy-Authorization"]
	if len(authStr) > 0 {
		if data, err := base64.StdEncoding.DecodeString(strings.TrimLeft(authStr[0], "Basic ")); err == nil {
			auth := strings.SplitN(string(data), ":", 2)
			if len(auth) == 2 {
				ctx.User = &User{auth[0], auth[1]}
				if !global.AllowAnonymous && !ctx.User.Authorized() {
					w.Header().Set("Proxy-Authenticate", fmt.Sprintf(`Basic realm="%v on %v"`, Tag, host))
					w.WriteHeader(http.StatusProxyAuthRequired)
					return
				}
			} else {
				w.Header().Set("Proxy-Authenticate", fmt.Sprintf(`Basic realm="%v on %v"`, Tag, host))
				w.WriteHeader(http.StatusProxyAuthRequired)
				return
			}
		} else {
			w.Header().Set("Proxy-Authenticate", fmt.Sprintf(`Basic realm="%v on %v"`, Tag, host))
			w.WriteHeader(http.StatusProxyAuthRequired)
			return
		}
		r.Header.Del("Proxy-Authorization")
	} else if !global.AllowAnonymous {
		w.Header().Set("Proxy-Authenticate", fmt.Sprintf(`Basic realm="%v on %v"`, Tag, host))
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	r.Header.Del("Proxy-Connection")
	if r.Method == "CONNECT" {
		s.HandleConnect(ctx, w, r)
	} else if strings.ToLower(r.Header.Get("Upgrade")) == "websocket" {
		s.HandleWebSocketUpgrade(ctx, w, r)
	} else {
		s.HandlePlain(ctx, w, r)
	}
}

func (s *SmartProxy) HandlePlain(ctx *ProxyContext, w http.ResponseWriter, r *http.Request) {
	ctx.Logger.SetPrefix(fmt.Sprintf("[HTTP][%d][%v][%v][%v] ", ctx.counter, r.RemoteAddr, r.Method, r.Host))

	defer r.Body.Close()

	if global.NoCaching {
		r.Header.Del("If-Modified-Since")
		r.Header.Del("Cache-Control")
	}

	r.RequestURI = ""
	if resp, err := tr.RoundTrip(r); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	} else {
		defer resp.Body.Close()
		if global.NoCaching {
			resp.Header.Del("Expires")
			resp.Header.Del("Last-Modified")
			resp.Header.Del("Cache-Control")
			resp.Header.Add("Cache-Control", "no-cache")
		}

		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.Header().Add("Proxy-Agent", Tag)
		w.WriteHeader(resp.StatusCode)
		done := make(chan bool, 1)
		go func() {
			written, err := io.Copy(w, resp.Body)
			ctx.Printf("Copied %d bytes from upstream[%v] to client[%v]. Error: %v", written, r.Host, r.RemoteAddr, err)
			done <- (err == nil)
		}()
		<-done
	}
}

func (s *SmartProxy) HandleConnect(ctx *ProxyContext, w http.ResponseWriter, r *http.Request) {
	ctx.Logger.SetPrefix(fmt.Sprintf("[CONN][%d][%v][%v] ", ctx.counter, r.RemoteAddr, r.Host))

	h, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "webserver doesn't support hijacking", http.StatusBadGateway)
		return
	}
	cc, _, err := h.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer cc.Close()
	cc.Write([]byte(fmt.Sprintf("HTTP/%d.%d 200 Connection Established\r\n\r\n", r.ProtoMajor, r.ProtoMinor)))

	uc, err := net.DialTimeout("tcp", r.Host, global.UpstreamDialTimeout)
	if err != nil {
		ctx.Println(err)
		return
	}
	defer uc.Close()
	ctx.Printf("Connected to upstream %v, addr: %v", r.Host, uc.RemoteAddr())

	done := make(chan bool, 1)
	go func() {
		written, err := io.Copy(uc, cc)
		ctx.Printf("Copied %d bytes from client[%v] to upstream[%v]. Error: %v", written, cc.RemoteAddr(), r.Host, err)
		done <- true
	}()
	go func() {
		written, err := io.Copy(cc, uc)
		ctx.Printf("Copied %d bytes from upstream[%v] to client[%v]. Error: %v", written, r.Host, cc.RemoteAddr(), err)
		done <- true
	}()
	for n := 0; n < 2; n++ {
		<-done
	}
}

func (s *SmartProxy) HandleWebSocketUpgrade(ctx *ProxyContext, w http.ResponseWriter, r *http.Request) {
	ctx.Logger.SetPrefix(fmt.Sprintf("[WebSocket][%d][%v] ", ctx.counter, r.RemoteAddr))
	http.Error(w, "Unimplemented WebSocket Upgrade proxy. Expect modern WS implementation to CONNECT directly.", http.StatusMethodNotAllowed)
	ctx.Println("Unimplemented WebSocket Upgrade proxy")
}

func main() {
	var port int
	flag.StringVar(&host, "h", "proxy.localdomain", "Host used to identify proxy built-in web service")
	ipv4Only := flag.Bool("4", true, "Listen on IPV4 only, required by Linux platform.")
	flag.IntVar(&port, "p", 3128, "proxy listening port")
	version := flag.Bool("v", false, "display build version")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, Tag, versionString)
		fmt.Fprintln(os.Stderr, "Usage:")
		flag.PrintDefaults()
	}
	flag.Parse()

	if version != nil && *version {
		fmt.Fprintln(os.Stdout, versionString)
		return
	}

	s := &http.Server{
		Addr:           ":" + strconv.Itoa(port),
		Handler:        new(SmartProxy),
		MaxHeaderBytes: 1 << 20,
	}

	addr := s.Addr
	if addr == "" {
		addr = ":http"
	}

	l, e := net.Listen(
		func() string {
			if *ipv4Only {
				return "tcp4"
			} else {
				return "tcp"
			}
		}(), addr)
	if e != nil {
		log.Panic(e)
	}
	defer l.Close()

	log.Println(s.Serve(l))
}
