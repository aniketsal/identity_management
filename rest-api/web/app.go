package web

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"golang.ngrok.com/ngrok"
	"golang.ngrok.com/ngrok/config"
)

// OrgSetup contains organization's config to interact with the network.
type OrgSetup struct {
	OrgName      string
	MSPID        string
	CryptoPath   string
	CertPath     string
	KeyPath      string
	TLSCertPath  string
	PeerEndpoint string
	GatewayPeer  string
	Gateway      client.Gateway
}

func startTunnel(ctx context.Context) error {
	listener, err := ngrok.Listen(ctx,
		config.HTTPEndpoint(
			config.WithDomain("oryx-modern-carefully.ngrok-free.app"),
		),
		ngrok.WithAuthtokenFromEnv(),
	)
	if err != nil {
		return err
	}

	// Return the public URL of the tunnel
	fmt.Println("App URL", listener.URL())
	return http.Serve(listener, nil)
}

// Serve starts http web server.
func Serve(setups OrgSetup) {
	// ctx := context.Background()
	// listener, err := startTunnel(ctx)
	// if err != nil {
	// 	fmt.Println(err)
	// }

	http.HandleFunc("/AddStudent", setups.AddStudent)
	http.HandleFunc("/GetStudentDetails", setups.GetStudentDetails)
	http.HandleFunc("/CheckStudent", setups.CheckStudent)
	http.HandleFunc("/IsStudentRegister", setups.IsStudentRegister)
	http.HandleFunc("/LogIn", setups.LogIn)
	http.HandleFunc("/UpdatePassword", setups.UpdatePassword)
	if err := startTunnel(context.Background()); err != nil {
		fmt.Println(err)
	}
}
