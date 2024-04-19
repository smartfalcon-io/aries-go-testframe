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

	// CreateDIDErrorCode for create did error.
	CreateSchemaErrorCode

	// GetSchemaErrorCode for create did error
	GetShemaErrorCode

	// CreateCredDefErrorCode for create did error
	CreateCredDefErrorCode

	// GetCredDefErrorCode for create did error
	GetCredDefErrorCode
)

const (
	// command name.
	CommandName = "libvdr"

	// command methods.
	CreateSchemaCommandMethod  = "CreateSchema"
	GetSchemaCommandMethod = "GetSchema"
	CreateCredDefCommandMethod = "CreateCredDef"
	GetCredDefCommandMethod = "GetCredDef"

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
		cmdutil.NewCommandHandler(CommandName, GetSchemaCommandMethod, o.GetSchema),
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

type GetSchemaRequest struct{
	SchemaId string
}

type CreateCredDefRequest struct{
	Seed string
	Did string
	SchemaId string
	CredDefTag string
}

type GetCredDefRequest struct{
	CredDefId string
}

// GetSchema method to get schema
func (o *Command) GetSchema(rw io.Writer, req io.Reader) command.Error {

	var request GetSchemaRequest

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetSchemaCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	genesisJSON := `{"reqSignature":{},"txn":{"data":{"data":{"alias":"Node1","blskey":"4N8aUNHSgjQVgkpm8nhNEfDf6txHznoYREg9kirmJrkivgL4oSEimFF6nsQ6M41QvhM2Z33nves5vfSn9n1UwNFJBYtWVnHYMATn76vLuL3zU88KyeAYcHfsih3He6UHcXDxcaecHVz6jhCYz1P2UZn2bDVruL5wXpehgBfBaLKm3Ba","blskey_pop":"RahHYiCvoNCtPTrVtP7nMC5eTYrsUA8WjXbdhNc8debh1agE9bGiJxWBXYNFbnJXoXhWFMvyqhqhRoq737YQemH5ik9oL7R4NTTCz2LEZhkgLJzB3QRQqJyBNyv7acbdHrAT8nQ9UkLbaVL9NBpnWXBTw4LEMePaSHEw66RzPNdAX1","client_ip":"138.197.138.255","client_port":9702,"node_ip":"138.197.138.255","node_port":9701,"services":["VALIDATOR"]},"dest":"Gw6pDLhcBcoQesN72qfotTgFa7cbuqZpkX3Xo6pLhPhv"},"metadata":{"from":"Th7MpTaRZVRYnPiabds81Y"},"type":"0"},"txnMetadata":{"seqNo":1,"txnId":"fea82e10e894419fe2bea7d96296a6d46f50f93f9eeda954ec461b2ed2950b62"},"ver":"1"}`

    // Create a Reader from the JSON string
    genesisReader := strings.NewReader(genesisJSON)

    // Wrap the Reader into a ReadCloser
    genesisReadCloser := io.NopCloser(genesisReader)

	client, err := indyvdr.New(genesisReadCloser)
	if err != nil {
		logutil.LogError(logger, CommandName, GetSchemaCommandMethod, "unable to connect: "+err.Error())

		return command.NewValidationError(GetShemaErrorCode, fmt.Errorf("unable to connect: %w", err))
	}

	err = client.RefreshPool()
	if err != nil {
		logutil.LogError(logger, CommandName,GetSchemaCommandMethod, "unable to get pool status: "+err.Error())

		return command.NewValidationError(GetShemaErrorCode, fmt.Errorf("unable to get pool status: %w", err))
	}

	schemaresponse, err := client.GetSchema(request.SchemaId)
	if err != nil {
		logutil.LogError(logger, CommandName, GetSchemaCommandMethod, "error while requesting schema: "+err.Error())

		return command.NewValidationError(GetShemaErrorCode, fmt.Errorf("error while requesting schema: %w", err))
	}

	var attrNames []interface{}
	var name string
	var VeRsion string
	if m, ok := schemaresponse.Data.(map[string]interface{}); ok {
		// Access elements inside the map by their keys
		attrNames = m["attr_names"].([]interface{})
		name = m["name"].(string)
		VeRsion = m["version"].(string)
	}
	response := struct {
		Name string
		SeqNo uint32
		Version  string
		Attrnames []interface{}
	}{
		Name: name,
		SeqNo: schemaresponse.SeqNo,
		Version: VeRsion,
		Attrnames:  attrNames,
	}

	command.WriteNillableResponse(rw, response, logger)

	logutil.LogDebug(logger, CommandName, GetSchemaCommandMethod, "success")

	return nil

}

// Createschema create schema.
func (o *Command) CreateSchema(rw io.Writer, req io.Reader) command.Error {

	var request CreateSchemaRequest

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateSchemaCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	genesisJSON := `{"reqSignature":{},"txn":{"data":{"data":{"alias":"Node1","blskey":"4N8aUNHSgjQVgkpm8nhNEfDf6txHznoYREg9kirmJrkivgL4oSEimFF6nsQ6M41QvhM2Z33nves5vfSn9n1UwNFJBYtWVnHYMATn76vLuL3zU88KyeAYcHfsih3He6UHcXDxcaecHVz6jhCYz1P2UZn2bDVruL5wXpehgBfBaLKm3Ba","blskey_pop":"RahHYiCvoNCtPTrVtP7nMC5eTYrsUA8WjXbdhNc8debh1agE9bGiJxWBXYNFbnJXoXhWFMvyqhqhRoq737YQemH5ik9oL7R4NTTCz2LEZhkgLJzB3QRQqJyBNyv7acbdHrAT8nQ9UkLbaVL9NBpnWXBTw4LEMePaSHEw66RzPNdAX1","client_ip":"138.197.138.255","client_port":9702,"node_ip":"138.197.138.255","node_port":9701,"services":["VALIDATOR"]},"dest":"Gw6pDLhcBcoQesN72qfotTgFa7cbuqZpkX3Xo6pLhPhv"},"metadata":{"from":"Th7MpTaRZVRYnPiabds81Y"},"type":"0"},"txnMetadata":{"seqNo":1,"txnId":"fea82e10e894419fe2bea7d96296a6d46f50f93f9eeda954ec461b2ed2950b62"},"ver":"1"}`

    // Create a Reader from the JSON string
    genesisReader := strings.NewReader(genesisJSON)

    // Wrap the Reader into a ReadCloser
    genesisReadCloser := io.NopCloser(genesisReader)

	client, err := indyvdr.New(genesisReadCloser)
	if err != nil {
		logutil.LogError(logger, CommandName, CreateSchemaCommandMethod, "unable to connect: "+err.Error())

		return command.NewValidationError(CreateSchemaErrorCode, fmt.Errorf("unable to connect: %w", err))
	}

	err = client.RefreshPool()
	if err != nil {
		logutil.LogError(logger, CommandName, CreateSchemaCommandMethod, "unable to get pool status: "+err.Error())

		return command.NewValidationError(CreateSchemaErrorCode, fmt.Errorf("unable to get pool status: %w", err))
	}

	var IssuerDidseed = request.Seed

	seed, err := indyvdr.ConvertSeed(IssuerDidseed[0:32])
	if err != nil {
		logutil.LogError(logger, CommandName, CreateSchemaCommandMethod, "unable to get convert seed: "+err.Error())

		return command.NewValidationError(CreateSchemaErrorCode, fmt.Errorf("unable to get convert seed: %w", err))
	}

	var pubkey ed25519.PublicKey
	var privkey ed25519.PrivateKey
	privkey = ed25519.NewKeyFromSeed(seed)
	pubkey = privkey.Public().(ed25519.PublicKey)

	mysig := indyvdr.NewSigner(pubkey, privkey)

	var attrs []string
    for  _,value := range request.Schema.Attributes {
	attrs = append(attrs, value)
    }
	response, err := client.CreateSchema(request.Did, request.Schema.Name, request.Schema.Version, attrs, mysig)
	if err != nil {
		logutil.LogError(logger, CommandName, CreateSchemaCommandMethod, "unable to create schema: "+err.Error())

		return command.NewValidationError(CreateSchemaErrorCode, fmt.Errorf("error while creating schema: %w", err))
	}

	command.WriteNillableResponse(rw, response, logger)

	logutil.LogDebug(logger, CommandName, CreateSchemaCommandMethod, "success")

	return nil
}

// GetCredDef method to get credential defination
func (o *Command) GetCredDef(rw io.Writer, req io.Reader) command.Error {

	var request GetCredDefRequest

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, GetCredDefCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	genesisJSON := `{"reqSignature":{},"txn":{"data":{"data":{"alias":"Node1","blskey":"4N8aUNHSgjQVgkpm8nhNEfDf6txHznoYREg9kirmJrkivgL4oSEimFF6nsQ6M41QvhM2Z33nves5vfSn9n1UwNFJBYtWVnHYMATn76vLuL3zU88KyeAYcHfsih3He6UHcXDxcaecHVz6jhCYz1P2UZn2bDVruL5wXpehgBfBaLKm3Ba","blskey_pop":"RahHYiCvoNCtPTrVtP7nMC5eTYrsUA8WjXbdhNc8debh1agE9bGiJxWBXYNFbnJXoXhWFMvyqhqhRoq737YQemH5ik9oL7R4NTTCz2LEZhkgLJzB3QRQqJyBNyv7acbdHrAT8nQ9UkLbaVL9NBpnWXBTw4LEMePaSHEw66RzPNdAX1","client_ip":"138.197.138.255","client_port":9702,"node_ip":"138.197.138.255","node_port":9701,"services":["VALIDATOR"]},"dest":"Gw6pDLhcBcoQesN72qfotTgFa7cbuqZpkX3Xo6pLhPhv"},"metadata":{"from":"Th7MpTaRZVRYnPiabds81Y"},"type":"0"},"txnMetadata":{"seqNo":1,"txnId":"fea82e10e894419fe2bea7d96296a6d46f50f93f9eeda954ec461b2ed2950b62"},"ver":"1"}`

    // Create a Reader from the JSON string
    genesisReader := strings.NewReader(genesisJSON)

    // Wrap the Reader into a ReadCloser
    genesisReadCloser := io.NopCloser(genesisReader)

	client, err := indyvdr.New(genesisReadCloser)
	if err != nil {
		logutil.LogError(logger, CommandName, GetCredDefCommandMethod, "unable to connect: "+err.Error())

		return command.NewValidationError(GetCredDefErrorCode, fmt.Errorf("unable to connect: %w", err))
	}

	err = client.RefreshPool()
	if err != nil {
		logutil.LogError(logger, CommandName,GetCredDefCommandMethod, "unable to get pool status: "+err.Error())

		return command.NewValidationError(GetCredDefErrorCode, fmt.Errorf("unable to get pool status: %w", err))
	}

	creddefresponse, err := client.GetCredDef(request.CredDefId)
	if err != nil {
		logutil.LogError(logger, CommandName, GetCredDefCommandMethod, "error while getting cred def: "+err.Error())

		return command.NewValidationError(GetCredDefErrorCode, fmt.Errorf("error while getting cred def: %w", err))
	}

	response := struct {
		SignatureType string
		Ref           uint32
		Tag           string
		Data          interface{}
	}{
		SignatureType: creddefresponse.SignatureType,
		Ref:           creddefresponse.SeqNo,
		Tag:           creddefresponse.Tag,
		Data:          creddefresponse.Data, 
	}
     
	command.WriteNillableResponse(rw, response, logger)

	logutil.LogDebug(logger, CommandName, GetCredDefCommandMethod, "success")

	return nil
}

// CreateDef Method  to create credential defination
func (o *Command) CreateCredDef(rw io.Writer, req io.Reader) command.Error {

	var request CreateCredDefRequest

	err := json.NewDecoder(req).Decode(&request)
	if err != nil {
		logutil.LogInfo(logger, CommandName, CreateCredDefCommandMethod, err.Error())

		return command.NewValidationError(InvalidRequestErrorCode, fmt.Errorf("request decode : %w", err))
	}

	genesisJSON := `{"reqSignature":{},"txn":{"data":{"data":{"alias":"Node1","blskey":"4N8aUNHSgjQVgkpm8nhNEfDf6txHznoYREg9kirmJrkivgL4oSEimFF6nsQ6M41QvhM2Z33nves5vfSn9n1UwNFJBYtWVnHYMATn76vLuL3zU88KyeAYcHfsih3He6UHcXDxcaecHVz6jhCYz1P2UZn2bDVruL5wXpehgBfBaLKm3Ba","blskey_pop":"RahHYiCvoNCtPTrVtP7nMC5eTYrsUA8WjXbdhNc8debh1agE9bGiJxWBXYNFbnJXoXhWFMvyqhqhRoq737YQemH5ik9oL7R4NTTCz2LEZhkgLJzB3QRQqJyBNyv7acbdHrAT8nQ9UkLbaVL9NBpnWXBTw4LEMePaSHEw66RzPNdAX1","client_ip":"138.197.138.255","client_port":9702,"node_ip":"138.197.138.255","node_port":9701,"services":["VALIDATOR"]},"dest":"Gw6pDLhcBcoQesN72qfotTgFa7cbuqZpkX3Xo6pLhPhv"},"metadata":{"from":"Th7MpTaRZVRYnPiabds81Y"},"type":"0"},"txnMetadata":{"seqNo":1,"txnId":"fea82e10e894419fe2bea7d96296a6d46f50f93f9eeda954ec461b2ed2950b62"},"ver":"1"}`

    // Create a Reader from the JSON string
    genesisReader := strings.NewReader(genesisJSON)

    // Wrap the Reader into a ReadCloser
    genesisReadCloser := io.NopCloser(genesisReader)

	client, err := indyvdr.New(genesisReadCloser)
	if err != nil {
		logutil.LogError(logger, CommandName, CreateCredDefCommandMethod, "unable to connect: "+err.Error())

		return command.NewValidationError(CreateCredDefErrorCode, fmt.Errorf("unable to connect to network: %w", err))
	}

	err = client.RefreshPool()
	if err != nil {
		logutil.LogError(logger, CommandName, CreateCredDefCommandMethod, "unable to get pool status: "+err.Error())

		return command.NewValidationError(CreateCredDefErrorCode, fmt.Errorf("unable to get pool status: %w", err))
	}

	// private and public key for given seed
	var IssuerDidseed = request.Seed
	seed, err := indyvdr.ConvertSeed(IssuerDidseed[0:32])
	if err != nil {
		logutil.LogError(logger, CommandName, CreateCredDefCommandMethod, "unable to get convert seed: "+err.Error())

		return command.NewValidationError(CreateCredDefErrorCode, fmt.Errorf("unable to get convert seed: %w", err))
	}

	var pubkey ed25519.PublicKey
	var privkey ed25519.PrivateKey

	privkey = ed25519.NewKeyFromSeed(seed)
	pubkey = privkey.Public().(ed25519.PublicKey)

	mysig := indyvdr.NewSigner(pubkey, privkey)

	var primary = map[string]interface{}{
		"pubkey": pubkey,
	}
	var revocation = map[string]interface{}{
		"revoc": 0,
	}

	schemaresponse,err := client.GetSchema(request.SchemaId)
	if err != nil {
		logutil.LogError(logger, CommandName, CreateCredDefCommandMethod, "unable to get schema details: "+err.Error())

		return command.NewValidationError(CreateCredDefErrorCode, fmt.Errorf("unable to get schema details: %w", err))
	}

	response, err := client.CreateClaimDef(request.Did, schemaresponse.SeqNo,request.CredDefTag, primary, revocation, mysig)
	if err != nil {
		logutil.LogError(logger, CommandName, CreateCredDefCommandMethod, "unable to create cred def: "+err.Error())

		return command.NewValidationError(CreateCredDefErrorCode, fmt.Errorf("unable to create cred def: %w", err))
	}

	command.WriteNillableResponse(rw, response, logger)

	logutil.LogDebug(logger, CommandName, CreateCredDefCommandMethod, "success")

	return nil
}

