package reverse_proxy

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"github.com/google/seesaw/common/conn"
	"github.com/google/seesaw/common/seesaw"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"syscall"
	"time"

	log "github.com/golang/glog"
)

var defaultConfig = Config{
	ListenPort:  ":443",
	CertFile:    "/etc/seesaw/ssl/cert.pem",
	CertKeyFile: "/etc/seesaw/ssl/key.pem",
}

type Config struct {
	ListenPort  string
	CertFile    string
	CertKeyFile string
}

type RPS struct {
	cfg            *Config
	shutdown       chan bool
	shutdownListen chan bool
	haMaster       chan bool
	reloadCerts    chan bool
	listening      bool
	hostProxies    map[string]*httputil.ReverseProxy
	seesaw         *conn.Seesaw
	certHash       []byte
}

func DefaultConfig() Config {
	return defaultConfig
}

// New returns an initialised RPS struct.
func New(cfg *Config, seesaw *conn.Seesaw) *RPS {
	if cfg == nil {
		defaultCfg := DefaultConfig()
		cfg = &defaultCfg
	}

	return &RPS{
		cfg:            cfg,
		shutdown:       make(chan bool),
		shutdownListen: make(chan bool),
		haMaster:       make(chan bool),
		reloadCerts:    make(chan bool),
		listening:      false,
		hostProxies:    map[string]*httputil.ReverseProxy{},
		seesaw:         seesaw,
		certHash:       []byte(""),
	}
}

// Run starts the RPS.
func (e *RPS) Run() {
	go e.monitorState()
	go e.monitorCerts()

	for {
		select {
		case <-e.shutdown:
			e.shutdownListen <- true
			<-e.shutdownListen
			return
		case val := <-e.haMaster:
			if val && !e.listening {
				go e.listen()
			} else if !val && e.listening {
				e.shutdownListen <- true
				<-e.shutdownListen
			}
		}
	}

}

// listen starts the HTTPS listener
func (e *RPS) listen() {
	cert, err := tls.LoadX509KeyPair(e.cfg.CertFile, e.cfg.CertKeyFile)
	if err != nil {
		log.Fatalf("cannot load certificate or key: %v", err)
	}

	config := tls.Config{Certificates: []tls.Certificate{cert}, InsecureSkipVerify: false}
	//Make a TLS listener
	//ln, err := tls.Listen("tcp", e.cfg.ListenPort, &config)
	//if err != nil {
	//	log.Fatalf("cannot create listener: %v", err)
	//}
	httpHandler := customHandler{
		response: "",
		rps:      *e,
	}

	//TODO: Implement custom 403, 404, 503-page
	monitorHTTP := &http.Server{
		Addr:           e.cfg.ListenPort,
		TLSConfig:      &config,
		ReadTimeout:    10 * time.Second,
		Handler:        &httpHandler,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go monitorHTTP.ListenAndServeTLS(e.cfg.CertFile, e.cfg.CertKeyFile)

	e.listening = true
	log.Infof("listening on port %v for reverse proxy", e.cfg.ListenPort)

	select {
	case <-e.shutdownListen:
		monitorHTTP.Close()
		e.listening = false
		e.shutdownListen <- true
	case <-e.reloadCerts:
		monitorHTTP.Close()
		e.listening = false
	}
}

type customHandler struct {
	response string
	rps      RPS
}

// serves as a http handler and chooses which proxy we should forward the request to. Creates new ones as needed.
func (c *customHandler) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	//Uncomment this and add to condition per comment below if we get mixed-transport issues
	/*
		//Get IP protocol, default IPV6
		ip_proto := seesaw.AF(syscall.AF_INET6)
		if net.ParseIP(request.RemoteAddr).To4() != nil {
			ip_proto = seesaw.AF(syscall.AF_INET)
		}

	*/
	log.Infof("serving connection to: %v from %v", request.Host, request.RemoteAddr)
	//Check if we already have a proxy connection to this location
	proxy, ok := c.rps.hostProxies[request.Host]

	if ok {
		log.Infof("found old proxy, serving: %v", request.Host)
		proxy.ServeHTTP(writer, request)
		return
	}

	//Get vservers
	vservers, err := c.rps.seesaw.Vservers()
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
					target, err := url.Parse("http://" + targetIp + ":" + strconv.Itoa(int(service.Port)))

					if err != nil {
						log.Warningf("error parsing target IP: %v", err)
						return
					}

					log.Infof("did not find old proxy, making and serving: %v using IP: %v", request.Host, "http://"+targetIp+":"+strconv.Itoa(int(service.Port)))
					//newProxy := httputil.NewSingleHostReverseProxy(target)
					newProxy := &httputil.ReverseProxy{
						Rewrite: func(r *httputil.ProxyRequest) {
							r.SetURL(target)
							r.Out.Host = r.In.Host
						},
					}
					c.rps.hostProxies[request.Host] = newProxy
					newProxy.ServeHTTP(writer, request)
					return
				} else {
					log.Infof("host was not healthy, am not serving: %v", request.Host)
					writer.WriteHeader(http.StatusServiceUnavailable)
					writer.Write([]byte("503: Host not currently up"))
					return
				}
			}
		}

	}

	log.Infof("unknown host, forbidden: %v", request.Host)
	writer.WriteHeader(http.StatusForbidden)
	writer.Write([]byte("403: Host forbidden"))
	return
}

// Monitors the state of the engine HA, to shutdown listen if we are not the master
func (e *RPS) monitorState() {
	for {
		status, err := e.seesaw.HAStatus()
		if err != nil {
			log.Fatalf("error getting HA status: %v", err)
		}
		e.haMaster <- status.State == 4
		time.Sleep(5 * time.Second)
	}
}

func (e *RPS) monitorCerts() {
	for {
		f, err := os.Open(e.cfg.CertFile)
		if err != nil {
			log.Warningf("cannot open cert file for update check: %v", err)
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			log.Warningf("could not compute hash of cert file: %v", err)
		}

		if hash := h.Sum(nil); !bytes.Equal(hash, e.certHash) {
			log.Infof("Certificate changed on disk, reloading..")
			e.certHash = hash
			e.reloadCerts <- true
		}
		time.Sleep(60 * time.Second)
	}
}

// Shutdown signals the RPS server to shutdown.
func (e *RPS) Shutdown() {
	e.shutdown <- true
}
