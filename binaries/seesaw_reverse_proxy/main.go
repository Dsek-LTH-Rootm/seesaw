package main

import (
	"flag"
	log "github.com/golang/glog"
	"github.com/google/seesaw/common/conn"
	"github.com/google/seesaw/common/ipc"
	"github.com/google/seesaw/common/seesaw"
	"github.com/google/seesaw/common/server"
	"github.com/google/seesaw/reverse_proxy"
)

var (
	seesawReverseProxy *reverse_proxy.RPS
	seesawConn         *conn.Seesaw
	listenPort         = flag.String("listen_port", string(443), "Reverse proxy listen port")
	certFile           = flag.String("cert_file", "/etc/seesaw/ssl/cert.pem", "Reverse proxy certificate file")
	certKeyFile        = flag.String("cert_key_file", "/etc/seesaw/ssl/key.pem", "Reverse proxy certificate private key file")
)

func main() {
	flag.Parse()

	ctx := ipc.NewTrustedContext(seesaw.SCReverseProxy)

	var err error
	seesawConn, err = conn.NewSeesawIPC(ctx)
	if err != nil {
		log.Fatalf("Failed to connect to engine: %v", err)
	}

	rpsCfg := reverse_proxy.DefaultConfig(seesawConn)
	rpsCfg.ListenPort = *listenPort
	rpsCfg.CertFile = *certFile
	rpsCfg.CertKeyFile = *certKeyFile

	rps := reverse_proxy.New(&rpsCfg)
	server.ShutdownHandler(rps)
	rps.Run()
}
