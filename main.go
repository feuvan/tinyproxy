package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
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
var allowAnonymous = false

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
	ctx.SetPrefix(fmt.Sprintf("[Core][%d][%v] ", ctx.counter, r.RemoteAddr))
	ctx.Printf("%v", r.URL)

	authStr := r.Header["Proxy-Authorization"]
	if len(authStr) > 0 {
		if data, err := base64.StdEncoding.DecodeString(strings.TrimLeft(authStr[0], "Basic ")); err == nil {
			auth := strings.SplitN(string(data), ":", 2)
			if len(auth) == 2 {
				ctx.User = &User{auth[0], auth[1]}
				if !allowAnonymous && !ctx.User.Authorized() {
					w.Header().Set("Proxy-Authenticate", fmt.Sprintf(`Basic realm="%v on %v"`, Tag, host))
					http.Error(w, "", http.StatusProxyAuthRequired)
					return
				}
			} else {
				w.Header().Set("Proxy-Authenticate", fmt.Sprintf(`Basic realm="%v on %v"`, Tag, host))
				http.Error(w, "", http.StatusProxyAuthRequired)
				return
			}
		} else {
			w.Header().Set("Proxy-Authenticate", fmt.Sprintf(`Basic realm="%v on %v"`, Tag, host))
			http.Error(w, err.Error(), http.StatusProxyAuthRequired)
			return
		}
		r.Header.Del("Proxy-Authorization")
	} else if !allowAnonymous {
		w.Header().Set("Proxy-Authenticate", fmt.Sprintf(`Basic realm="%v on %v"`, Tag, host))
		http.Error(w, "", http.StatusProxyAuthRequired)
		return
	}
	r.Header.Del("Proxy-Connection")

	if r.Header.Get("Upgrade") == "websocket" {
		s.HandleWebSocket(ctx, w, r)
	} else if r.Method == "CONNECT" {
		s.HandleHTTPS(ctx, w, r)
	} else {
		s.HandlePlain(ctx, w, r)
	}
}

func (s *SmartProxy) HandlePlain(ctx *ProxyContext, w http.ResponseWriter, r *http.Request) {
	ctx.Logger.SetPrefix(fmt.Sprintf("[HTTP][%d][%v] ", ctx.counter, r.RemoteAddr))
	ctx.Printf("current connected: %d", atomic.AddInt64(&s.connected, 1))
	defer func() {
		atomic.AddInt64(&s.connected, -1)
		ctx.Printf("Closed. current connected: %d", s.connected)
	}()

	nr, err := http.NewRequest(r.Method, r.RequestURI, r.Body)
	for k, vs := range r.Header {
		for _, v := range vs {
			nr.Header.Add(k, v)
		}
	}

	defer r.Body.Close()
	client := &http.Client{}
	resp, err := client.Do(nr)
	if err == nil {
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		b := make([]byte, 0x1000)
		for {
			n, err := resp.Body.Read(b)
			if n > 0 {
				w.Write(b[0:n])
			}
			if err != nil || n == 0 {
				if err != nil && err != io.EOF {
					ctx.Printf("Error: %v, n= %d", err, n)
				}
				break
			}
		}
	} else {
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
}

func (s *SmartProxy) HandleHTTPS(ctx *ProxyContext, w http.ResponseWriter, r *http.Request) {
	ctx.Logger.SetPrefix(fmt.Sprintf("[HTTPS][%d][%v] ", ctx.counter, r.RemoteAddr))
	ctx.Printf("current connected: %d", atomic.AddInt64(&s.connected, 1))
	defer func() {
		atomic.AddInt64(&s.connected, -1)
		ctx.Printf("Closed. current connected: %d", s.connected)
	}()

	h, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "", http.StatusBadGateway)
		return
	}
	cc, _, err := h.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	cc.Write([]byte(fmt.Sprintf("HTTP/%d.%d 200 OK\r\n\r\n", r.ProtoMajor, r.ProtoMinor)))

	conn, err := net.Dial("tcp", r.URL.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	} else {
		ctx.Printf("connected to %v", r.URL.Host)
	}

	go func() {
		written, err := io.Copy(conn, cc)
		ctx.Printf("Copied %d bytes from client[%v] to upstream[%v]. Error: %v", written, cc.RemoteAddr(), conn.RemoteAddr(), err)
	}()
	go func() {
		written, err := io.Copy(cc, conn)
		ctx.Printf("Copied %d bytes from upstream[%v] to client[%v]. Error: %v", written, conn.RemoteAddr(), cc.RemoteAddr(), err)
	}()
}

func (s *SmartProxy) HandleWebSocket(ctx *ProxyContext, w http.ResponseWriter, r *http.Request) {
	ctx.Logger.SetPrefix(fmt.Sprintf("[WebSocket][%d][%v] ", ctx.counter, r.RemoteAddr))
	ctx.Printf("current connected: %d", atomic.AddInt64(&s.connected, 1))
	defer func() {
		atomic.AddInt64(&s.connected, -1)
		ctx.Printf("Closed. current connected: %d", s.connected)
	}()
	http.Error(w, "Unimplemented WebSocket proxy", http.StatusMethodNotAllowed)
}

func main() {
	var port int
	flag.StringVar(&host, "h", "proxy.localdomain", "Host used to identify proxy built-in web service")
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
		Handler:        &SmartProxy{0, 0},
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}

	log.Println(s.ListenAndServe())
}
