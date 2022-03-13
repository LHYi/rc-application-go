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
	"github.com/jedib0t/go-pretty/v6/table"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// these address should be changed accordingly when implemented in the hardware
const (
	// the mspID should be identical to the one used when calling cryptogen to generate credential files
	// mspID         = "Org1MSP"
	// the path of the certificates
	cryptoPath  = "../../fabric-samples-2.4/test-network/organizations/peerOrganizations/org1.example.com"
	certPath    = cryptoPath + "/users/User1@org1.example.com/msp/signcerts/User1@org1.example.com-cert.pem"
	keyPath     = cryptoPath + "/users/User1@org1.example.com/msp/keystore/"
	tlsCertPath = cryptoPath + "/peers/peer0.org1.example.com/tls/ca.crt"
	// an IP address to access the peer node, it is a localhost address when the network is running in a single machine
	peerEndpoint = "localhost:7051"
	// name of the peer node
	gatewayPeer = "peer0.org1.example.com"
	// the channel name and the chaincode name should be identical to the ones used in blockchain network implementation, the following are the default values
	// these information have been designed to be entered by the application user
	// channelName   = "mychannel"
	// chaincodeName = "basic"
)

func main() {
	log.Println("============ application-golang starts ============")
	log.Println("============ The application will end when you enter exit ============")
	// DISCOVERY_AS_LOCALHOST should be set to "false" if the network is deployed on other computers
	for {
		log.Println("============ setting DISCOVERY_AS_LOCALHOST ============")
		fmt.Print("-> Do you want to set DISCOVERY_AS_LOCALHOST to true? [y/n]: ")
		// catchOneInput() catches one line of the terminal input, see more details in function definition
		DAL := catchOneInput()
		// determining whether DAL is yes or no and conduct corresponding operations
		if isNo(DAL) {
			log.Println("-> Setting DISCOVERY_AS_LOCALHOST to false")
			err := os.Setenv("DISCOVERY_AS_LOCALHOST", "false")
			if err != nil {
				log.Fatalf("Error setting DISCOVERY_AS_LOCALHOST environemnt variable: %v", err)
				// an exit code that is nonzero indicates that there exist an error
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
	// set up a gateway connection to access the blockchain network
	log.Println("============ trying to connect to gateway ============")
	// define the variable outside the loop so that it can be used in the following connection configuration
	var userName string
	// label of the code block is useful when the process of running the code is relatec to the user's selection
	// labels are only used with goto, continue and break
userNameLoop:
	for {
		log.Println("-> Please enter your username:")
		userName = catchOneInput()
	userNameConfirmLoop:
		for {
			// formatted output, %s prints out the value of a string
			fmt.Printf("-> Please confirm your username is %s, [y/n]: ", userName)
			userNameConfirm := catchOneInput()
			if isYes(userNameConfirm) {
				break userNameLoop
			} else if isNo(userNameConfirm) {
				break userNameConfirmLoop
			} else {
				fmt.Println("->Wrong input! Please try again.")
			}
		}
	}
	log.Printf("-> Your username is %s.", userName)

	log.Println("============ enrolling user", userName, "============")
	// The gRPC client connection should be shared by all Gateway connections to this endpoint
	clientConnection := newGrpcConnection()
	defer clientConnection.Close()
	// generation of identity files
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

	// the logic is similar to the code above
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
				fmt.Println("->Wrong input! Please try again.")
			}
		}
	}
	log.Printf("-> Your network name is %s.", networkName)

	network := gateway.GetNetwork(networkName)
	log.Println("============ successfully connected to network", networkName, "============")

	// the logic is similar to the code above
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
				fmt.Println("->Wrong input! Please try again.")
			}
		}
	}
	log.Printf("-> Your contract name is %s.", contractName)
	contract := network.GetContract(contractName)
	log.Println("============ successfully got contract", contractName, "============")

	for {
		fmt.Println("-> Please enter the name of the smart contract function you want to invoke, enter help to print the functions available")
		scfunction := catchOneInput()
		invokeChaincode(contract, scfunction, userName)
		// here provides another way to exit the application after every invocation of the smart contract function
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
				fmt.Println("->Wrong input! Please try again.")
				continue scContinueConfirmLoop
			}
		}
	}
}

// TODO: this function can be further seperated into several functions in the future
func invokeChaincode(contract *client.Contract, scfunction string, userName string) {
	// the defer function is important in handling error
	// once the chaincode invocation is unsuccessful, the panic function will be called and the recover function which is deferred before the error exists
	// will allow the program to print out the error and recover to the next line after the line that caused error
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("Occured an error while invoking chiancode function: %v...Recovered, please try again.\n", r)
		}
	}()
	switch scfunction {
	case "instantiate", "Instantiate", "INSTANTIATE":
		instantiate(contract)
	case "issue", "Issue", "ISSUE":
		log.Println("============ Issuing a new credit ============")
		// in the issuing process, functions are added to allow the credit details to be automatically generated
	issueLoop:
		for {
			var creditNumber string
		enterCreditNumberLoop:
			for {
				fmt.Println("-> Do you want to assign a specific credit number? [y/n]: ")
				enterConfirm := catchOneInput()
				if isYes(enterConfirm) {
					fmt.Println("-> Please enter the credit number:")
					creditNumber = catchOneInput()
					fmt.Println("-> The credit number you entered is: " + creditNumber)
					break enterCreditNumberLoop
				} else if isNo(enterConfirm) {
					fmt.Println("-> Generating credit number.")
					creditNumber = generateCreditNumber()
					fmt.Println("-> The credit number automatically generated is: " + creditNumber)
					break enterCreditNumberLoop
				} else {
					fmt.Println("->Wrong input! Please try again.")
				}
			}
			var issuer string
		enterIssuerLoop:
			for {
				fmt.Println("-> Do you want to use your username as issuer? [y/n]: ")
				enterConfirm := catchOneInput()
				if isYes(enterConfirm) {
					fmt.Println("-> Using your username as the issuer")
					issuer = userName
					fmt.Println("-> The issuer is: " + userName)
					break enterIssuerLoop
				} else if isNo(enterConfirm) {
					fmt.Println("-> Please enter the issuer: ")
					issuer = catchOneInput()
					fmt.Println("-> The issuer you entered is: " + issuer)
					break enterIssuerLoop
				} else {
					fmt.Println("->Wrong input! Please try again.")
				}
			}
			var issueDateTime string
		enterCreditDateTimeLoop:
			for {
				fmt.Println("-> Do you want to generate the issue date and time of the credit automatically? [y/n]: ")
				enterConfirm := catchOneInput()
				if isYes(enterConfirm) {
					fmt.Println("-> Getting date and time.")
					issueDateTime = generateCreditDateTime()
					fmt.Println("-> The date and time is: " + issueDateTime)
					break enterCreditDateTimeLoop
				} else if isNo(enterConfirm) {
					fmt.Println("-> Please enter the issue date and time:")
					issueDateTime = catchOneInput()
					fmt.Println("-> The issue date and time you entered is: " + issueDateTime)
					break enterCreditDateTimeLoop
				} else {
					fmt.Println("->Wrong input! Please try again.")
				}
			}
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
					fmt.Println("->Wrong input! Please try again.")
				}
			}
		}
	case "query", "Query", "QUERY":
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
					fmt.Println("->Wrong input! Please try again.")
				}
			}
		}
	case "help", "HELP", "Help", "":
		listFuncs()
	default:
		fmt.Println("->Wrong input! Please try again!")
	}
}

// instantiate function do nothing, but it can be used to verify whether the connection is successful before interacting with the ledger
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
	// submit transaction is usually used in the case where an update of the ledger is required
	_, err := contract.SubmitTransaction("Issue", creditNumber, issuer, issueDateTime)
	if err != nil {
		panic(fmt.Errorf("failed to submit transaction: %w", err))
	}

	fmt.Printf("*** Transaction committed successfully\n")
}

// querying an existing credit
func query(contract *client.Contract, creditNumber string, issuer string) {
	fmt.Printf("Evaluate Transaction: QueryCredit, function returns credit attributes\n")
	// evaluate transaction is usually used in the case where only querying the world state is required
	evaluateResult, err := contract.EvaluateTransaction("Query", creditNumber, issuer)
	if err != nil {
		panic(fmt.Errorf("failed to evaluate transaction: %w", err))
	}
	result := formatJSON(evaluateResult)

	fmt.Printf("*** Result:%s\n", result)
}

// the following are util functions following the GO package document
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

// Format JSON data for pretty printing credit details in JSON format
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

// catchOneInput() catches one line of the terminal input, ended with \n, it returns a string where \n is stripped
func catchOneInput() string {
	// instantiate a new reader
	reader := bufio.NewReader(os.Stdin)
	s, _ := reader.ReadString('\n')
	// get rid of the \n at the end of the string
	s = strings.Replace(s, "\n", "", -1)
	// if the string is exit, exit the application directly
	// this allows the user to exit the application whereever they want and saves the effort of detecting the exit command elsewhere
	if isExit(s) {
		exitApp()
	}
	return s
}

// safely exit application
func exitApp() {
	log.Println("============ application-golang ends ============")
	// exit code zero indicates that no error occurred
	os.Exit(0)
}

// list functions that can be invoked and their arguments
// a individual package is used to pretty print a table, see https://github.com/jedib0t/go-pretty/tree/main/table for details of using this package
func listFuncs() {
	tof := table.NewWriter()
	// directing the output to the system standard output
	tof.SetOutputMirror(os.Stdout)
	// add one row as the table header
	tof.AppendHeader(table.Row{"Commend", "Function discription", "Arguments", "Argument discription"})
	// the beginning of the table content
	tof.AppendRows([]table.Row{
		{"list", "List out all the functions that can be called and the arguments required.", "", ""},
	})
	// add one line of seperators between two rows
	tof.AppendSeparator()
	// multiple lines with no seperators in the middle
	tof.AppendRows([]table.Row{
		{"issue", "The issue function collects the information of a new credit and submit a transaction proposal to the blockchain network to issue a new credit.", "credit number", "Credit number is the unique ID number of a credit."},
		{"", "", "issuer", "Issuer is the unique identity of the entity which issues this credit."},
		{"", "", "issue date and time", "The date and time when the credit is issued."},
	})
	tof.AppendSeparator()
	tof.AppendRows([]table.Row{
		{"query", "The query function collects the information of an existing credit and submit a evaluation proposal to the world state to query the details of that credit.", "credit number", "Credit number is the unique ID number of a credit."},
		{"", "", "issuer", "Issuer is the unique identity of the entity which issues this credit."},
	})
	// print out the formatted table
	tof.Render()
}

// generating the credit number and date time with current time
// TODO: needs to be modified according to the naming rule of the credit
func generateCreditNumber() string {
	var now = time.Now()
	creditNumber := []string{"Credit", fmt.Sprint(now.Unix()*1e3 + int64(now.Nanosecond())/1e6)}
	return strings.Join(creditNumber, "-")
}

func generateCreditDateTime() string {
	var now = time.Now()
	creditNumber := []string{"", fmt.Sprint(now.Unix()*1e3 + int64(now.Nanosecond())/1e6)}
	return strings.Join(creditNumber, "")
}
