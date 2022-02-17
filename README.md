# rc-application-go

This repo contains the applications developed for the response credit scenario.

### Running the GO program

The usage of the applications should be based on an Hyperledger Fabric blockchain network with response credit contract implemented.

Once the blockchain network has been brought up and the chaincode has been successfully commited, one can run the following command to start the application.

```
cd application-gateway-VPPO
go run application-gateway-VPPO.go
```

or 

```
cd application-gateway-DER
go run application-gateway-DER.go
```

### Running the applications as executable files

Compile the VPPO application with the go build command.

    cd application-gateway-VPPO
    go build

Once the program is successfully built, there will exist an executable file named "application-gateway-VPPO" in the folder (it will be an .exe file in Windows). Run it and you will be able to interact with the application via terminal.

Similarly, the DER application can be commited using the following commands.

    cd application-gateway-DER
    go build

### Interacting with the blockchain network as VPPO

In this section you will learn how to use the VPPO application.

#### Environment setup

The blockchain network can either be brought up within a single machine (local host) or within a network consisting of multiple machines.

If the blockchain network is implemented in a single machine, setting ```DISCOVERY_AS_LOCALHOST``` to ```true```. Otherwise, set ```DISCOVERY_AS_LOCALHOST``` to ```false```

#### Enroll

At current stage, since the application is tested with the test network provided by fabric samples, VPPO is interacting with the blockchain network as Organization 1, thus its MSP is Org1MSP. This can be changed accordingly later when implemented within a customeized network.

The application will first 