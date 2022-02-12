package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	gwproto "github.com/hyperledger/fabric-protos-go/gateway"
	"github.com/hyperledger/fabric-sdk-go/pkg/core/config"
	"github.com/hyperledger/fabric-sdk-go/pkg/gateway"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// currently working as Org1 on Peer0
//TODO: to be changed when implemented in Raspberry PI
const (
	mspID        = "Org1MSP"
	cryptoPath   = "../../fabric-samples/test-network/organizations/peerOrganizations/org1.example.com"
	ccpPath      = cryptoPath + "/connection-org1.yaml"
	certPath     = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/cert.pem"
	keyDir       = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
	tlsCertPath  = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	peerEndpoint = "localhost:7051"
	gatewayPeer  = "peer0.org1.example.com"
	// channelName   = "mychannel"
	// chaincodeName = "basic"
	// userName	  = "appUser"
)

// Using the timestamp as the assetID
var now = time.Now()
var assetId = fmt.Sprintf("asset%d", now.Unix()*1e3+int64(now.Nanosecond())/1e6)

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
		log.Println("-> Please confirm your username is", userName, ": [y/n]")
		userNameConfirm, _ := reader.ReadString('\n')
		userNameConfirm = strings.Replace(userNameConfirm, "\n", "", -1)
		if strings.Compare(userNameConfirm, "Y") == 0 || strings.Compare(userNameConfirm, "y") == 0 {
			break
		}
	}

	log.Println("============ enrolling user %s ============", userName)
	log.Println("============ creating wallet ============")
	wallet, err := gateway.NewFileSystemWallet("wallet")
	if err != nil {
		log.Fatalf("Failed to create wallet: %v", err)
		os.Exit(1)
	}
	if wallet.Exists(userName) {
		log.Println("-> User", userName, "already exists!")
	}
	if !wallet.Exists(userName) {
		err = populateWallet(wallet, userName)
		if err != nil {
			log.Fatalf("Failed to populate wallet contents: %v", err)
			os.Exit(1)
		}
	}
	log.Println("============ successfully enroll user ", userName, "============")
	log.Println("============ connecting to gateway ============")
	gw, err := gateway.Connect(
		gateway.WithConfig(config.FromFile(filepath.Clean(ccpPath))),
		gateway.WithIdentity(wallet, userName),
	)
	if err != nil {
		log.Fatalf("Failed to connect to gateway: %v", err)
		os.Exit(1)
	}
	defer gw.Close()

	var networkName string
	log.Println("============ connecting to network ============")
	for {
		log.Println("-> Please enter the name of the network:")
		networkName, _ = reader.ReadString('\n')
		networkName = strings.Replace(networkName, "\n", "", -1)
		log.Println("-> Please confirm your network name is", networkName, ": [y/n]")
		networkNameConfirm, _ := reader.ReadString('\n')
		networkNameConfirm = strings.Replace(networkNameConfirm, "\n", "", -1)
		if strings.Compare(networkNameConfirm, "Y") == 0 || strings.Compare(networkNameConfirm, "y") == 0 {
			break
		}
	}

	//TODO: needs to be changed accordingly
	network, err := gw.GetNetwork(networkName)
	if err != nil {
		log.Fatalf("Failed to get network: %v", err)
		os.Exit(1)
	}
	log.Println("-> successfully connected to network ", networkName)

	var contractName string
	log.Println("============ getting contract ============")
	for {
		log.Println("-> Please enter the name of the contract:")
		contractName, _ = reader.ReadString('\n')
		contractName = strings.Replace(contractName, "\n", "", -1)
		log.Println("-> Please confirm your contract name is %v: [y/n]", contractName)
		contractNameConfirm, _ := reader.ReadString('\n')
		contractNameConfirm = strings.Replace(contractNameConfirm, "\n", "", -1)
		if strings.Compare(contractNameConfirm, "Y") == 0 || strings.Compare(contractNameConfirm, "y") == 0 {
			break
		}
	}

	//TODO: needs to be changed accordingly
	contract := network.GetContract(contractName)
	log.Printf("-> successfully got contract ", contractName)

scfunctionloop:
	for {
		fmt.Print("-> Please enter the name of the smart contract function you want to invoke")
		scfunction, _ := reader.ReadString('\n')
		scfunction = strings.Replace(scfunction, "\n", "", -1)
		// TODO: waiting to be changed accordingly
		switch scfunction {
		case "instantiate":
			instantiate(contract)
		// case "issue":
		// 	issue(contract)
		case "exit":
			break scfunctionloop
		default:
			fmt.Println("Wrong input! Please try again!")

		}
	}

	log.Println("============ application-golang ends ============")
}

func populateWallet(wallet *gateway.Wallet, username string) error {
	log.Println("============ Populating wallet ============")

	cert, err := ioutil.ReadFile(filepath.Clean(certPath))
	if err != nil {
		return err
	}

	// the keyDir should contain a single file, which is the private key
	files, err := ioutil.ReadDir(keyDir)
	if err != nil {
		return err
	}
	if len(files) != 1 {
		return fmt.Errorf("keystore folder should have contain one file")
	}

	keyPath := filepath.Join(keyDir, files[0].Name())
	key, err := ioutil.ReadFile(filepath.Clean(keyPath))
	if err != nil {
		return err
	}

	identity := gateway.NewX509Identity("Org1MSP", string(cert), string(key))

	return wallet.Put(username, identity)
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
func newIdentity() *identity.X509Identity {
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
	files, err := ioutil.ReadDir(keyDir)
	if err != nil {
		panic(fmt.Errorf("failed to read private key directory: %w", err))
	}
	privateKeyPEM, err := ioutil.ReadFile(path.Join(keyDir, files[0].Name()))

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

// The following are the functions corresponding to the functions defined in the smart contract
// The instantiate function do nothing but the required setup of the ledger
func instantiate(contract *gateway.Contract) {
	fmt.Printf("Submit Transaction: Instantiate, function calls the instantiate function, with no effect")

	_, err := contract.SubmitTransaction("Instantiate")
	if err != nil {
		panic(fmt.Errorf("failed to instantiate: %w", err))
	}

	fmt.Printf("*** Transaction committed successfully\n")
}

// Evaluate a transaction to query ledger state.
func getAllAssets(contract *client.Contract) {
	fmt.Println("Evaluate Transaction: GetAllAssets, function returns all the current assets on the ledger")

	evaluateResult, err := contract.EvaluateTransaction("GetAllAssets")
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}
	result := formatJSON(evaluateResult)

	fmt.Printf("*** Result:%s\n", result)
}

// Issuing a new response credit
// Submit a transaction synchronously, blocking until it has been committed to the ledger.
func issueCredit(contract *client.Contract, issuer string, creditNumber string, issueDateTime string) {
	fmt.Printf("Submit Transaction: IssueCredit, creates new response credit with credit issuer, credit number and credit issueDateTime")

	_, err := contract.SubmitTransaction("Issue", issuer, creditNumber, issueDateTime)
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}

	fmt.Printf("*** Transaction committed successfully\n")
}

// Evaluate a transaction by assetID to query ledger state.
func readAssetByID(contract *client.Contract) {
	fmt.Printf("Evaluate Transaction: ReadAsset, function returns asset attributes\n")

	evaluateResult, err := contract.EvaluateTransaction("ReadAsset", assetId)
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}
	result := formatJSON(evaluateResult)

	fmt.Printf("*** Result:%s\n", result)
}

/*
Submit transaction asynchronously, blocking until the transaction has been sent to the orderer, and allowing
this thread to process the chaincode response (e.g. update a UI) without waiting for the commit notification
*/
func transferAssetAsync(contract *client.Contract) {
	fmt.Printf("Async Submit Transaction: TransferAsset, updates existing asset owner'\n")

	submitResult, commit, err := contract.SubmitAsync("TransferAsset", client.WithArguments(assetId, "Mark"))
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction asynchronously: %w", err))
	}

	fmt.Printf("Successfully submitted transaction to transfer ownership from %s to Mark. \n", string(submitResult))
	fmt.Println("Waiting for transaction commit.")

	if status, err := commit.Status(); err != nil {
		panic(fmt.Errorf("failed to get commit status: %w", err))
	} else if !status.Successful {
		panic(fmt.Errorf("transaction %s failed to commit with status: %d", status.TransactionID, int32(status.Code)))
	}

	fmt.Printf("*** Transaction committed successfully\n")
}

// Submit transaction, passing in the wrong number of arguments ,expected to throw an error containing details of any error responses from the smart contract.
func exampleErrorHandling(contract *client.Contract) {
	fmt.Println("Submit Transaction: UpdateAsset asset70, asset70 does not exist and should return an error")

	_, err := contract.SubmitTransaction("UpdateAsset")
	if err != nil {
		switch err := err.(type) {
		case *client.EndorseError:
			fmt.Printf("Endorse error with gRPC status %v: %s\n", status.Code(err), err)
		case *client.SubmitError:
			fmt.Printf("Submit error with gRPC status %v: %s\n", status.Code(err), err)
		case *client.CommitStatusError:
			if errors.Is(err, context.DeadlineExceeded) {
				fmt.Printf("Timeout waiting for transaction %s commit status: %s", err.TransactionID, err)
			} else {
				fmt.Printf("Error obtaining commit status with gRPC status %v: %s\n", status.Code(err), err)
			}
		case *client.CommitError:
			fmt.Printf("Transaction %s failed to commit with status %d: %s\n", err.TransactionID, int32(err.Code), err)
		}
		/*
		 Any error that originates from a peer or orderer node external to the gateway will have its details
		 embedded within the gRPC status error. The following code shows how to extract that.
		*/
		statusErr := status.Convert(err)
		for _, detail := range statusErr.Details() {
			errDetail := detail.(*gwproto.ErrorDetail)
			fmt.Printf("Error from endpoint: %s, mspId: %s, message: %s\n", errDetail.Address, errDetail.MspId, errDetail.Message)
		}
	}
}

//Format JSON data
func formatJSON(data []byte) string {
	var prettyJSON bytes.Buffer
	if err := json.Indent(&prettyJSON, data, " ", ""); err != nil {
		panic(fmt.Errorf("failed to parse JSON: %w", err))
	}
	return prettyJSON.String()
}
