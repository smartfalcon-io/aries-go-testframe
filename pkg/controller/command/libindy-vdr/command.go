/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package libvdr

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/hyperledger/aries-framework-go/pkg/common/log"
	"github.com/hyperledger/aries-framework-go/pkg/controller/command"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/libvdr"
	"github.com/hyperledger/aries-framework-go/pkg/internal/logutil"
	indyvdr "github.com/hyperledger/aries-framework-go/pkg/libvdr"
)

var logger = log.New("aries-framework/command/libvdr")

// Error codes.
const (
	// InvalidRequestErrorCode is typically a code for invalid requests.
	InvalidRequestErrorCode = command.Code(iota + command.VDR)

	// SaveDIDErrorCode for save did error.
	SaveDIDErrorCode

	// GetDIDErrorCode for get did error.
	GetDIDErrorCode

	// ResolveDIDErrorCode for get did error.
	ResolveDIDErrorCode

	// CreateDIDErrorCode for create did error.
	CreateDIDErrorCode
)

const (
	// command name.
	CommandName = "libvdr"

	// command methods.
	CreateSchemaCommandMethod  = "CreateSchema"

	// error messages.
	errEmptyTrusteeSeed   = "Trustee seed is mandatory"
	errNoGenesis     = "genesis file is mandatory"
	errEmptySchema = "SchemaID is mandatory"

	// log constants.
	didID = "did"
)

type provider interface {
	LIBVDRegistry() vdrapi.LibRegistry
}

// Command contains command operations provided by vdr controller.
type Command struct {
	ctx      provider
}

// New returns new vdr controller command instance.
func New(ctx provider) (*Command, error) {

	return &Command{
		ctx:      ctx,
	}, nil
}

func (o *Command) GetHandlers() []command.Handler {
	return []command.Handler{
		cmdutil.NewCommandHandler(CommandName, CreateSchemaCommandMethod, o.CreateSchema),
	}
}

// type Schema struct{
// 	Name string
// 	Version string
// 	Attributes Map[string]string 
// }

// type CreateSchemaRequest struct {
// 	Seed string
// 	Schema Schema
// }

type CreateSchemaRequest struct {
	Seed   string
	Did    string
	Schema struct {
		Name       string
		Version    string
		Attributes map[string]string
	}
}

// Createschema create schema.
func (o *Command) CreateSchema(rw io.Writer, req io.Reader) command.Error {
	var request CreateSchemaRequest

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateSchemaCommandMethod, err.Error())
		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	// if request.Genesis == "" {
	// 	logutil.LogDebug(logger, CommandName,CreateSchemaCommandMethod, errNoGenesis)
	// 	return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf(errNoGenesis))
	// }
    // genesisReader := strings.NewReader(request.Genesis)
    // genesisReadCloser := io.NopCloser(genesisReader)
	genesisJSON := `{"reqSignature":{},"txn":{"data":{"data":{"alias":"Node1","blskey":"4N8aUNHSgjQVgkpm8nhNEfDf6txHznoYREg9kirmJrkivgL4oSEimFF6nsQ6M41QvhM2Z33nves5vfSn9n1UwNFJBYtWVnHYMATn76vLuL3zU88KyeAYcHfsih3He6UHcXDxcaecHVz6jhCYz1P2UZn2bDVruL5wXpehgBfBaLKm3Ba","blskey_pop":"RahHYiCvoNCtPTrVtP7nMC5eTYrsUA8WjXbdhNc8debh1agE9bGiJxWBXYNFbnJXoXhWFMvyqhqhRoq737YQemH5ik9oL7R4NTTCz2LEZhkgLJzB3QRQqJyBNyv7acbdHrAT8nQ9UkLbaVL9NBpnWXBTw4LEMePaSHEw66RzPNdAX1","client_ip":"138.197.138.255","client_port":9702,"node_ip":"138.197.138.255","node_port":9701,"services":["VALIDATOR"]},"dest":"Gw6pDLhcBcoQesN72qfotTgFa7cbuqZpkX3Xo6pLhPhv"},"metadata":{"from":"Th7MpTaRZVRYnPiabds81Y"},"type":"0"},"txnMetadata":{"seqNo":1,"txnId":"fea82e10e894419fe2bea7d96296a6d46f50f93f9eeda954ec461b2ed2950b62"},"ver":"1"}`

    // Create a Reader from the JSON string
    genesisReader := strings.NewReader(genesisJSON)

    // Wrap the Reader into a ReadCloser
    genesisReadCloser := io.NopCloser(genesisReader)
	client, err := indyvdr.New(genesisReadCloser)
	if err != nil {
		logutil.LogError(logger, CommandName, CreateSchemaCommandMethod, "unable to connect: "+err.Error())
	}

	err = client.RefreshPool()
	if err != nil {
		logutil.LogError(logger, CommandName, CreateSchemaCommandMethod, "unable to get pool status: "+err.Error())
	}

	// didDoc := &did.Doc{}

	// if len(request.DID) != 0 {
	// 	didDoc, err = did.ParseDocument(request.DID)
	// 	if err != nil {
	// 		logutil.LogError(logger, CommandName, CreateDIDCommandMethod, "parse did doc: "+err.Error())

	// 		return command.NewValidationError(CreateDIDErrorCode, fmt.Errorf("parse did doc: %w", err))
	// 	}
	// }

	// opts := make([]vdrapi.DIDMethodOption, 0)

	// for k, v := range request.Opts {
	// 	opts = append(opts, vdrapi.WithOption(k, v))
	// }

	var IssuerDidseed = request.Seed

	seed, err := indyvdr.ConvertSeed(IssuerDidseed[0:32])
	if err != nil {
		logutil.LogError(logger, CommandName, CreateSchemaCommandMethod, "unable to get convert seed: "+err.Error())
	}

	var pubkey ed25519.PublicKey
	var privkey ed25519.PrivateKey
	privkey = ed25519.NewKeyFromSeed(seed)
	pubkey = privkey.Public().(ed25519.PublicKey)
	// did, err := indyvdr.CreateDID(&indyvdr.MyDIDInfo{PublicKey: pubkey, Cid: true, MethodName: "sov"})
	// if err != nil {
	// 	logutil.LogError(logger, CommandName, CreateSchemaCommandMethod, "unable to create did from seed: "+err.Error())
	// }

	// var didvalue string

	// parts := strings.Split(did.String(), ":")
	// if len(parts) >= 3 {
	// 	didvalue = parts[2]
	// } else {
	// 	logutil.LogError(logger, CommandName, CreateSchemaCommandMethod, "unalbe to get didvalue: "+err.Error())
	// }

	mysig := indyvdr.NewSigner(pubkey, privkey)


	// var attrs = []string{request.Schema.Attributes.(string)}

	var attrs = make([]string, 0)
    for key, value := range request.Schema.Attributes {
	attr := fmt.Sprintf("%s:%s", key, value)
	attrs = append(attrs, attr)
}
    // var attrs = []string{"sample1", "sample2"}
	response, err := client.CreateSchema(request.Did, request.Schema.Name, request.Schema.Version, attrs, mysig)
	if err != nil {
		logutil.LogError(logger, CommandName, CreateSchemaCommandMethod, "create schema: "+err.Error())

		return command.NewValidationError(CreateDIDErrorCode, fmt.Errorf("schema: %w", err))
	}

	// docBytes, err := doc.DIDDocument.JSONBytes()
	// if err != nil {
	// 	logutil.LogError(logger, CommandName, CreateSchemaCommandMethod, "unmarshal did doc: "+err.Error())

	// 	return command.NewValidationError(CreateDIDErrorCode, fmt.Errorf("unmarshal did doc: %w", err))
	// }

	command.WriteNillableResponse(rw, response, logger)

	logutil.LogDebug(logger, CommandName, CreateSchemaCommandMethod, "success")

	return nil
}

func (o *Command) GetSchema(rw io.Writer, req io.Reader) command.Error {}

