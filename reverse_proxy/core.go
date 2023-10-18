package reverse_proxy

import (
	"crypto/tls"
	"github.com/google/seesaw/common/conn"
	"github.com/google/seesaw/common/seesaw"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"syscall"
	"time"

	log "github.com/golang/glog"
)

var defaultConfig = Config{
	ListenPort:  string(rune(443)),
	CertFile:    "/etc/seesaw/ssl/cert.pem",
	CertKeyFile: "/etc/seesaw/ssl/key.pem",
	seesaw:      nil,
}

type Config struct {
	ListenPort  string
	CertFile    string
	CertKeyFile string
	seesaw      *conn.Seesaw
}

type RPS struct {
	cfg            *Config
	shutdown       chan bool
	shutdownListen chan bool
	hostProxies    map[string]*httputil.ReverseProxy
}

func DefaultConfig(conn *conn.Seesaw) Config {
	defaultConfig.seesaw = conn
	return defaultConfig
}

// New returns an initialised RPS struct.
func New(cfg *Config) *RPS {
	if cfg == nil {
		defaultCfg := DefaultConfig(nil)
		cfg = &defaultCfg
	}

	return &RPS{
		cfg:            cfg,
		shutdown:       make(chan bool),
		shutdownListen: make(chan bool),
		hostProxies:    map[string]*httputil.ReverseProxy{},
	}
}

// Run starts the RPS.
func (e *RPS) Run() {

	go e.listen()

	<-e.shutdown
	e.shutdownListen <- true
	<-e.shutdownListen
}

// monitoring starts an HTTP server for monitoring purposes.
func (e *RPS) listen() {
	cert, err := tls.LoadX509KeyPair(e.cfg.CertFile, e.cfg.CertKeyFile)
	if err != nil {
		log.Fatal("cannot load certificate or key:", err)
	}

	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: false}
	//Make a TLS listener
	ln, err := tls.Listen("tcp", e.cfg.ListenPort, &config)
	if err != nil {
		log.Fatal("cannot create listener:", err)
	}

	monitorHTTP := &http.Server{
		ReadTimeout:    30 * time.Second,
		Handler:        &customHandler{},
		WriteTimeout:   30 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go monitorHTTP.ServeTLS(ln, e.cfg.CertFile, e.cfg.CertKeyFile)

	log.Infof("listening on port %v for reverse proxy", e.cfg.ListenPort)

	<-e.shutdownListen
	err = ln.Close()
	e.shutdownListen <- true
}

type customHandler struct {
	response string
	rps      RPS
}

func (c *customHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	//Uncomment this and add to condition per comment below if we get mixed-transport issues
	/*
		//Get IP protocol, default IPV6
		ip_proto := seesaw.AF(syscall.AF_INET6)
		if net.ParseIP(request.RemoteAddr).To4() != nil {
			ip_proto = seesaw.AF(syscall.AF_INET)
		}

	*/

	//Check if we already have a proxy connection to this location
	proxy, ok := c.rps.hostProxies[request.Host]

	if ok {
		proxy.ServeHTTP(writer, request)
		return
	}

	//Get vservers
	vservers, err := c.rps.cfg.seesaw.Vservers()
	if err != nil {
		log.Warningf("error getting vservers: %v", err)
		return
	}

	//Find the target host in our Vservers, since we do not have a proxy there already

	if vserver, ok := vservers[request.Host]; ok {
		//Loop through all services for this host (IPv4/IPv6 transport services)
		for service := range vserver.Services {
			if service.Proto == syscall.IPPROTO_TCP {
				//Maybe add && service.AF == ip_proto to condition below if we get weird mixed-transport issues
				if vserver.Services[service].Healthy {
					//Get target ip, default to ipv6, change if the service address family is ipv4
					targetIp := vserver.IPv6Addr.String()
					if service.AF == seesaw.AF(syscall.AF_INET) {
						targetIp = vserver.IPv4Addr.String()
					}

					//Parse the target url. Does not need part after the port, the proxy fixes that
					target, err := url.Parse("http://" + targetIp + strconv.Itoa(int(service.Port)))

					if err != nil {
						log.Warningf("error parsing target IP: %v", err)
						return
					}

					newProxy := httputil.NewSingleHostReverseProxy(target)
					c.rps.hostProxies[request.Host] = newProxy
					newProxy.ServeHTTP(writer, request)
					return
				} else {
					writer.Write([]byte("503: Host not currently up"))
				}
			}
		}

	}

	writer.Write([]byte("403: Host forbidden"))
	return
}

// Shutdown signals the RPS server to shutdown.
func (e *RPS) Shutdown() {
	e.shutdown <- true
}
