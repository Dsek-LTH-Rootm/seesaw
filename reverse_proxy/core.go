package reverse_proxy

import (
	"crypto/tls"
	"github.com/google/seesaw/engine/config"
	"net"
	"net/http"
	"time"

	log "github.com/golang/glog"
)

var defaultConfig = Config{
	ListenPort:  string(443),
	CertFile:    "/etc/seesaw/ssl/cert.pem",
	CertKeyFile: "/etc/seesaw/ssl/key.pem",
}

type Config struct {
	ListenPort  string
	CertFile    string
	CertKeyFile string
	Cluster     config.Cluster
}

type RPS struct {
	cfg            *Config
	shutdown       chan bool
	shutdownListen chan bool
}

func DefaultConfig() Config {
	return defaultConfig
}

// New returns an initialised RPS struct.
func New(cfg *Config) *RPS {
	if cfg == nil {
		defaultCfg := DefaultConfig()
		cfg = &defaultCfg
	}

	return &RPS{
		cfg:            cfg,
		shutdown:       make(chan bool),
		shutdownListen: make(chan bool),
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
		WriteTimeout:   30 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	go monitorHTTP.ServeTLS(ln, e.cfg.CertFile, e.cfg.CertKeyFile)

	log.Infof("listening on port %v for reverse proxy", e.cfg.ListenPort)

	for {
		conn, err := ln.Accept()
		shouldBreak := false
		select {
		case <-e.shutdownListen:
			{
				e.shutdownListen <- true
				shouldBreak = true
				break
			}
		default:
		}

		if shouldBreak {
			break
		}

		if err != nil {
			log.Warningf("error in accepting new connection to RPS: %s", err)
		}

		go handle(conn)
	}

	<-e.shutdownListen
	err = ln.Close()
	e.shutdownListen <- true
}

func handle(clientConn net.Conn) {
	tlsconn, ok := clientConn.(*tls.Conn)
	if ok {
		err := tlsconn.Handshake()
		if err != nil {
			log.Warningf("error in tls handshake for %s: %s", clientConn.RemoteAddr(), err)
			clientConn.Close()
			return
		}

	}
}

// Shutdown signals the RPS server to shutdown.
func (e *RPS) Shutdown() {
	e.shutdown <- true
}
