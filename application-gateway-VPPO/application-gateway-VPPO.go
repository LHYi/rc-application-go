package main

import (
	"bufio"
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	// mspID         = "Org1MSP"
	cryptoPath   = "../../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
	certPath     = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem"
	keyPath      = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
	tlsCertPath  = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint = "localhost:7051"
	gatewayPeer  = "peer0.org1.example.com"
	// channelName   = "mychannel"
	// chaincodeName = "basic"
)

var now = time.Now()
var creditNumber = fmt.Sprintf("asset%d", now.Unix()*1e3+int64(now.Nanosecond())/1e6)

func main() {
	log.Println("============ application-golang starts ============")

	reader := bufio.NewReader(os.Stdin)
	//! DISCOVERY_AS_LOCALHOST should be set to "false" if the network is deployed on other computers
	for {
		log.Println("============ setting DISCOVERY_AS_LOCALHOST ============")
		fmt.Print("-> Do you want to set DISCOVERY_AS_LOCALHOST to true? [y/n]: ")
		DAL, _ := reader.ReadString('\n')
		DAL = strings.Replace(DAL, "\n", "", -1)
		if strings.Compare(DAL, "N") == 0 || strings.Compare(DAL, "n") == 0 {
			log.Println("-> Setting DISCOVERY_AS_LOCALHOST to false")
			err := os.Setenv("DISCOVERY_AS_LOCALHOST", "false")
			if err != nil {
				log.Fatalf("Error setting DISCOVERY_AS_LOCALHOST environemnt variable: %v", err)
				os.Exit(1)
			}
			log.Println("-> Success")
			break
		} else if strings.Compare(DAL, "Y") == 0 || strings.Compare(DAL, "y") == 0 {
			log.Println("-> Setting DISCOVERY_AS_LOCALHOST to true")
			err := os.Setenv("DISCOVERY_AS_LOCALHOST", "true")
			if err != nil {
				log.Fatalf("Error setting DISCOVERY_AS_LOCALHOST environemnt variable: %v", err)
				os.Exit(1)
			}
			log.Println("-> Success")
			break
		} else if strings.Compare(DAL, "exit") == 0 {
			log.Println("-> Exiting application")
			os.Exit(0)
		} else {
			log.Println("-> Wrong input, please try again or input exit")
		}
	}

	var userName string
	for {
		log.Println("============ trying to connect to gateway ============")
		log.Println("-> Please enter your username:")
		userName, _ = reader.ReadString('\n')
		userName = strings.Replace(userName, "\n", "", -1)
		fmt.Printf("-> Please confirm your username is %v, [y/n]: ", userName)
		userNameConfirm, _ := reader.ReadString('\n')
		userNameConfirm = strings.Replace(userNameConfirm, "\n", "", -1)
		if strings.Compare(userNameConfirm, "Y") == 0 || strings.Compare(userNameConfirm, "y") == 0 {
			break
		}
	}

	log.Println("============ enrolling user", userName, "============")
	// The gRPC client connection should be shared by all Gateway connections to this endpoint
	clientConnection := newGrpcConnection()
	defer clientConnection.Close()

	id := newIdentity(userName)
	sign := newSign()

	log.Println("============ successfully enroll user", userName, "============")
	log.Println("============ connecting to gateway ============")

	// Create a Gateway connection for a specific client identity
	gateway, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithClientConnection(clientConnection),
		// Default timeouts for different gRPC calls
		client.WithEvaluateTimeout(5*time.Second),
		client.WithEndorseTimeout(15*time.Second),
		client.WithSubmitTimeout(5*time.Second),
		client.WithCommitStatusTimeout(1*time.Minute),
	)
	if err != nil {
		panic(err)
	}
	defer gateway.Close()

	var networkName string
	log.Println("============ connecting to network ============")
	for {
		log.Println("-> Please enter the name of the network:")
		networkName, _ = reader.ReadString('\n')
		networkName = strings.Replace(networkName, "\n", "", -1)
		fmt.Printf("-> Please confirm your network name is: %v, [y/n]", networkName)
		networkNameConfirm, _ := reader.ReadString('\n')
		networkNameConfirm = strings.Replace(networkNameConfirm, "\n", "", -1)
		if strings.Compare(networkNameConfirm, "Y") == 0 || strings.Compare(networkNameConfirm, "y") == 0 {
			break
		}
	}

	network := gateway.GetNetwork(networkName)
	log.Println("-> successfully connected to network", networkName)

	var contractName string
	log.Println("============ getting contract ============")
	for {
		log.Println("-> Please enter the name of the contract:")
		contractName, _ = reader.ReadString('\n')
		contractName = strings.Replace(contractName, "\n", "", -1)
		fmt.Printf("-> Please confirm your contract name is: %v, [y/n]", contractName)
		contractNameConfirm, _ := reader.ReadString('\n')
		contractNameConfirm = strings.Replace(contractNameConfirm, "\n", "", -1)
		if strings.Compare(contractNameConfirm, "Y") == 0 || strings.Compare(contractNameConfirm, "y") == 0 {
			break
		}
	}
	contract := network.GetContract(contractName)
	log.Printf("-> successfully got contract %s", contractName)

scfunctionloop:
	for {
		fmt.Println("-> Please enter the name of the smart contract function you want to invoke")
		scfunction, _ := reader.ReadString('\n')
		scfunction = strings.Replace(scfunction, "\n", "", -1)
		// TODO: waiting to be changed accordingly
		switch scfunction {
		case "instantiate":
			instantiate(contract)
		case "issue":
		issueloop:
			for {
				log.Println("============ Issuing a new credit ============")
				fmt.Println("-> Please enter the credit number:")
				creditNumber, _ := reader.ReadString('\n')
				creditNumber = strings.Replace(creditNumber, "\n", "", -1)
				fmt.Println("-> The credit number you entered is: " + creditNumber)
				fmt.Println("-> Please enter the issuer:")
				issuer, _ := reader.ReadString('\n')
				issuer = strings.Replace(issuer, "\n", "", -1)
				fmt.Println("-> The issuer you entered is: " + issuer)
				fmt.Println("-> Please enter the issue date and time:")
				issueDateTime, _ := reader.ReadString('\n')
				issueDateTime = strings.Replace(issueDateTime, "\n", "", -1)
				fmt.Println("-> The issue date and time you entered is: " + issueDateTime)
				fmt.Println("-> Are these input correct? [y/n]")
				issueConfirm, _ := reader.ReadString('\n')
				issueConfirm = strings.Replace(issueConfirm, "\n", "", -1)
				if strings.Compare(issueConfirm, "Y") == 0 || strings.Compare(issueConfirm, "y") == 0 {
					issueCredit(contract, creditNumber, issuer, issueDateTime)
					break issueloop
				}
			}
		case "queryCredit":
		queryloop:
			for {
				log.Println("============ Querying a credit ============")
				fmt.Println("-> Please enter the credit number:")
				creditNumber, _ := reader.ReadString('\n')
				creditNumber = strings.Replace(creditNumber, "\n", "", -1)
				fmt.Println("-> The credit number you entered is: " + creditNumber)
				fmt.Println("-> Please enter the issuer:")
				issuer, _ := reader.ReadString('\n')
				issuer = strings.Replace(issuer, "\n", "", -1)
				fmt.Println("-> The issuer you entered is: " + issuer)
				fmt.Println("-> Are these input correct? [y/n]")
				queryConfirm, _ := reader.ReadString('\n')
				queryConfirm = strings.Replace(queryConfirm, "\n", "", -1)
				if strings.Compare(queryConfirm, "Y") == 0 || strings.Compare(queryConfirm, "y") == 0 {
					queryCredit(contract, creditNumber, issuer)
					break queryloop
				}
			}
		case "exit":
			break scfunctionloop
		default:
			fmt.Println("Wrong input! Please try again!")

		}
	}

	log.Println("============ application-golang ends ============")
}

func instantiate(contract *client.Contract) {
	log.Println("Submit Transaction: Instantiate, function calls the instantiate function, with no effect.")

	_, err := contract.SubmitTransaction("Instantiate")
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}

	fmt.Printf("*** Transaction committed successfully!\n")
}

// Issuing a new response credit
// Submit a transaction synchronously, blocking until it has been committed to the ledger.
func issueCredit(contract *client.Contract, creditNumber string, issuer string, issueDateTime string) {
	log.Println("Submit Transaction: IssueCredit, creates new response credit with credit issuer, credit number and credit issueDateTime.")

	_, err := contract.SubmitTransaction("Issue", creditNumber, issuer, issueDateTime)
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}

	fmt.Printf("*** Transaction committed successfully\n")
}

func queryCredit(contract *client.Contract, creditNumber string, issuer string) {
	fmt.Printf("Evaluate Transaction: QueryCredit, function returns credit attributes\n")

	evaluateResult, err := contract.EvaluateTransaction("QueryCredit", issuer, creditNumber)
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}
	result := formatJSON(evaluateResult)

	fmt.Printf("*** Result:%s\n", result)
}

// newGrpcConnection creates a gRPC connection to the Gateway server.
func newGrpcConnection() *grpc.ClientConn {
	certificate, err := loadCertificate(tlsCertPath)
	if err != nil {
		panic(err)
	}

	certPool := x509.NewCertPool()
	certPool.AddCert(certificate)
	transportCredentials := credentials.NewClientTLSFromCert(certPool, gatewayPeer)

	connection, err := grpc.Dial(peerEndpoint, grpc.WithTransportCredentials(transportCredentials))
	if err != nil {
		panic(fmt.Errorf("failed to create gRPC connection: %w", err))
	}

	return connection
}

// newIdentity creates a client identity for this Gateway connection using an X.509 certificate.
func newIdentity(mspID string) *identity.X509Identity {
	certificate, err := loadCertificate(certPath)
	if err != nil {
		panic(err)
	}

	id, err := identity.NewX509Identity(mspID, certificate)
	if err != nil {
		panic(err)
	}

	return id
}

func loadCertificate(filename string) (*x509.Certificate, error) {
	certificatePEM, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	return identity.CertificateFromPEM(certificatePEM)
}

// newSign creates a function that generates a digital signature from a message digest using a private key.
func newSign() identity.Sign {
	files, err := ioutil.ReadDir(keyPath)
	if err != nil {
		panic(fmt.Errorf("failed to read private key directory: %w", err))
	}
	privateKeyPEM, err := ioutil.ReadFile(path.Join(keyPath, files[0].Name()))

	if err != nil {
		panic(fmt.Errorf("failed to read private key file: %w", err))
	}

	privateKey, err := identity.PrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		panic(err)
	}

	sign, err := identity.NewPrivateKeySign(privateKey)
	if err != nil {
		panic(err)
	}

	return sign
}

//Format JSON data
func formatJSON(data []byte) string {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, data, " ", ""); err != nil {
		panic(fmt.Errorf("failed to parse JSON: %w", err))
	}
	return prettyJSON.String()
}
