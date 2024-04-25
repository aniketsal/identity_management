package main

import (
	// "fmt"
	// "log"
	// "net/http"
	// "os"
	// "rest-api/web"
	// "time"

	//"github.com/gorilla/mux"
	//"github.com/hyperledger/fabric-gateway/pkg/client"
	//"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	//"github.com/hyperledger/fabric-sdk-go/pkg/gateway"

	"fmt"
	"log"
	"rest-api/web"
	"time"
)

type ScheduledTask struct {
	Id        string    `json:"id"`
	Execution time.Time `json:"execution"`
}

func main() {
	log.Println("============ Application starts ============")
	// network, err = configNet()
	// contract = network.GetContract("basic")
	// // _, err = contract.SubmitTransaction("InitLedger")
	// // if err != nil {
	// // 	log.Fatalf("error submitting chaincode transaction: %v", err)
	// // }
	// log.Println("============ End cn ============")
	// handleRequests()
	cryptoPath := "../../test-network/organizations/peerOrganizations/org1.example.com"
	orgConfig := web.OrgSetup{
		OrgName:      "Org1",
		MSPID:        "Org1MSP",
		CertPath:     cryptoPath + "/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem",
		KeyPath:      cryptoPath + "/users/User1@org1.example.com/msp/keystore/",
		TLSCertPath:  cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt",
		PeerEndpoint: "localhost:7051",
		GatewayPeer:  "peer0.org1.example.com",
	}
	orgSetup, err := web.Initialize(orgConfig)
	if err != nil {
		fmt.Println("Error initializing setup for Org1: ", err)
	}
	web.Serve(web.OrgSetup(*orgSetup))

}
