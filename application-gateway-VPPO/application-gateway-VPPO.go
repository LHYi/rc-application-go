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
	log.Println("============ The application will end when you enter exit ============")
	//! DISCOVERY_AS_LOCALHOST should be set to "false" if the network is deployed on other computers
	for {
		log.Println("============ setting DISCOVERY_AS_LOCALHOST ============")
		fmt.Print("-> Do you want to set DISCOVERY_AS_LOCALHOST to true? [y/n]: ")
		DAL := catchOneInput()
		if isNo(DAL) {
			log.Println("-> Setting DISCOVERY_AS_LOCALHOST to false")
			err := os.Setenv("DISCOVERY_AS_LOCALHOST", "false")
			if err != nil {
				log.Fatalf("Error setting DISCOVERY_AS_LOCALHOST environemnt variable: %v", err)
				os.Exit(1)
			}
			log.Println("-> Success")
			break
		} else if isYes(DAL) {
			log.Println("-> Setting DISCOVERY_AS_LOCALHOST to true")
			err := os.Setenv("DISCOVERY_AS_LOCALHOST", "true")
			if err != nil {
				log.Fatalf("Error setting DISCOVERY_AS_LOCALHOST environemnt variable: %v", err)
				os.Exit(1)
			}
			log.Println("-> Success")
			break
		} else {
			log.Println("-> Wrong input, please try again or input exit")
		}
	}

	log.Println("============ trying to connect to gateway ============")
	var userName string
userNameLoop:
	for {
		log.Println("-> Please enter your username:")
		userName = catchOneInput()
	userNameConfirmLoop:
		for {
			fmt.Printf("-> Please confirm your username is %s, [y/n]: ", userName)
			userNameConfirm := catchOneInput()
			if isYes(userNameConfirm) {
				break userNameLoop
			} else if isNo(userNameConfirm) {
				break userNameConfirmLoop
			} else {
				fmt.Println("Wrong input! Please try again.")
			}
		}
	}
	log.Printf("-> Your username is %s.", userName)

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
networkNameLoop:
	for {
		log.Println("-> Please enter the name of the network:")
		networkName = catchOneInput()
	networkNameConfirmLoop:
		for {
			fmt.Printf("-> Please confirm your network name is: %s, [y/n]: ", networkName)
			networkNameConfirm := catchOneInput()
			if isYes(networkNameConfirm) {
				break networkNameLoop
			} else if isNo(networkNameConfirm) {
				break networkNameConfirmLoop
			} else {
				fmt.Println("Wrong input! Please try again.")
			}
		}
	}
	log.Printf("-> Your network name is %s.", networkName)

	network := gateway.GetNetwork(networkName)
	log.Println("============ successfully connected to network", networkName, "============")

	var contractName string
	log.Println("============ getting contract ============")
contractNameLoop:
	for {
		log.Println("-> Please enter the name of the contract:")
		contractName = catchOneInput()
	contractNameConfirmLoop:
		for {
			fmt.Printf("-> Please confirm your contract name is: %v, [y/n]: ", contractName)
			contractNameConfirm := catchOneInput()
			if isYes(contractNameConfirm) {
				break contractNameLoop
			} else if isNo(contractNameConfirm) {
				break contractNameConfirmLoop
			} else {
				fmt.Println("Wrong input! Please try again.")
			}
		}
	}
	log.Printf("-> Your contract name is %s.", contractName)
	contract := network.GetContract(contractName)
	log.Println("============ successfully got contract", contractName, "============")

	for {
		fmt.Println("-> Please enter the name of the smart contract function you want to invoke:")
		scfunction := catchOneInput()
		invokeChaincode(contract, scfunction)
	scContinueConfirmLoop:
		for {
			fmt.Print("Do you want to continue? [y/n]: ")
			continueConfirm := catchOneInput()
			if isYes(continueConfirm) {
				fmt.Println("Preparing for invoking next smart contract function")
				break scContinueConfirmLoop
			} else if isNo(continueConfirm) {
				exitApp()
			} else {
				fmt.Println("Wrong input! Please try again.")
				continue scContinueConfirmLoop
			}
		}
	}
}

func invokeChaincode(contract *client.Contract, scfunction string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Occured an error while invoking chiancode function: %v...Recovered, please try again.\n", r)
		}
	}()
	switch scfunction {
	case "instantiate":
		instantiate(contract)
	case "issue":
		log.Println("============ Issuing a new credit ============")
	issueLoop:
		for {
			fmt.Println("-> Please enter the credit number:")
			creditNumber := catchOneInput()
			fmt.Println("-> The credit number you entered is: " + creditNumber)
			fmt.Println("-> Please enter the issuer:")
			issuer := catchOneInput()
			fmt.Println("-> The issuer you entered is: " + issuer)
			fmt.Println("-> Please enter the issue date and time:")
			issueDateTime := catchOneInput()
			fmt.Println("-> The issue date and time you entered is: " + issueDateTime)
		issueConfirmLoop:
			for {
				fmt.Printf("-> Are these inputs correct? [y/n]: ")
				issueConfirm := catchOneInput()
				if isYes(issueConfirm) {
					issue(contract, creditNumber, issuer, issueDateTime)
					break issueLoop
				} else if isNo(issueConfirm) {
					fmt.Println("-> Please enter the details of the credit to issue again.")
					break issueConfirmLoop
				} else {
					fmt.Println("Wrong input! Please try again.")
				}
			}
		}
	case "query":
		log.Println("============ Querying a credit ============")
	queryLoop:
		for {
			fmt.Println("-> Please enter the credit number:")
			creditNumber := catchOneInput()
			fmt.Println("-> The credit number you entered is: " + creditNumber)
			fmt.Println("-> Please enter the issuer:")
			issuer := catchOneInput()
			fmt.Println("-> The issuer you entered is: " + issuer)
		queryConfirmLoop:
			for {
				fmt.Printf("-> Are these inputs correct? [y/n]: ")
				queryConfirm := catchOneInput()
				if isYes(queryConfirm) {
					query(contract, creditNumber, issuer)
					break queryLoop
				} else if isNo(queryConfirm) {
					fmt.Println("-> Please enter the details of the credit to query again.")
					break queryConfirmLoop
				} else {
					fmt.Println("Wrong input! Please try again.")
				}
			}
		}
	default:
		fmt.Println("Wrong input! Please try again!")
	}
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
func issue(contract *client.Contract, creditNumber string, issuer string, issueDateTime string) {
	log.Println("Submit Transaction: IssueCredit, creates new response credit with credit issuer, credit number and credit issueDateTime.")

	_, err := contract.SubmitTransaction("Issue", creditNumber, issuer, issueDateTime)
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}

	fmt.Printf("*** Transaction committed successfully\n")
}

func query(contract *client.Contract, creditNumber string, issuer string) {
	fmt.Printf("Evaluate Transaction: QueryCredit, function returns credit attributes\n")

	evaluateResult, err := contract.EvaluateTransaction("Query", creditNumber, issuer)
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

// Format JSON data
func formatJSON(data []byte) string {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, data, " ", ""); err != nil {
		panic(fmt.Errorf("failed to parse JSON: %w", err))
	}
	return prettyJSON.String()
}

// returns the confirmation
func isYes(s string) bool {
	return strings.Compare(s, "Y") == 0 || strings.Compare(s, "y") == 0 || strings.Compare(s, "Yes") == 0 || strings.Compare(s, "yes") == 0
}

func isNo(s string) bool {
	return strings.Compare(s, "N") == 0 || strings.Compare(s, "n") == 0 || strings.Compare(s, "No") == 0 || strings.Compare(s, "no") == 0
}

func isExit(s string) bool {
	return strings.Compare(s, "Exit") == 0 || strings.Compare(s, "exit") == 0 || strings.Compare(s, "EXIT") == 0
}

// catch console input once
func catchOneInput() string {
	reader := bufio.NewReader(os.Stdin)
	s, _ := reader.ReadString('\n')
	s = strings.Replace(s, "\n", "", -1)
	if isExit(s) {
		exitApp()
	}
	return s
}

// exit application
func exitApp() {
	log.Println("============ application-golang ends ============")
	os.Exit(0)
}
