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
	ctx.Printf("%v", r.RequestURI)

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
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	for k, vs := range r.Header {
		for _, v := range vs {
			nr.Header.Add(k, v)
		}
	}

	defer r.Body.Close()
	client := &http.Client{}
	if resp, err := client.Do(nr); err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	} else {
		for k, vs := range resp.Header {
			for _, v := range vs {
				w.Header().Add(k, v)
			}
		}
		w.Header().Add("Proxy-Agent", Tag)
		done := make(chan bool, 1)
		go func() {
			written, err := io.Copy(w, resp.Body)
			ctx.Printf("Copied %d bytes from upstream[%v] to client[%v]. Error: %v", written, r.URL.Host, r.RemoteAddr, err)
			done <- err == nil
		}()

		select {
		case <-done:
		}
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
	cc.Write([]byte(fmt.Sprintf("HTTP/%d.%d 200 Connection Established\r\n\r\n", r.ProtoMajor, r.ProtoMinor)))

	conn, err := net.Dial("tcp", r.URL.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	} else {
		ctx.Printf("connected to %v, remote addr: %v", r.URL.Host, conn.RemoteAddr())
	}

	done := make(chan bool, 2)
	go func() {
		written, err := io.Copy(conn, cc)
		ctx.Printf("Copied %d bytes from client[%v] to upstream[%v]. Error: %v", written, cc.RemoteAddr(), r.URL.Host, err)
		done <- err == nil
	}()
	go func() {
		written, err := io.Copy(cc, conn)
		ctx.Printf("Copied %d bytes from upstream[%v] to client[%v]. Error: %v", written, r.URL.Host, cc.RemoteAddr(), err)
		done <- err == nil
	}()
	count := 0
	for {
		select {
		case <-done:
			count++
			if count == 2 {
				return
			}
		}
	}
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
