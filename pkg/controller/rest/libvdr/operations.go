/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package libvdr

import (

	"fmt"
	"net/http"


	"github.com/hyperledger/aries-framework-go/pkg/controller/command/libindy-vdr"
	"github.com/hyperledger/aries-framework-go/pkg/controller/internal/cmdutil"
	"github.com/hyperledger/aries-framework-go/pkg/controller/rest"
	vdrapi "github.com/hyperledger/aries-framework-go/pkg/framework/aries/api/libvdr"
)

// constants for the VDR operations.
const (
	VDROperationID    = "/libvdr"
	// vdrDIDPath        = VDROperationID + "/did"
	CreateSchema     = VDROperationID + "/createschema"
	Getschema        = VDROperationID + "/getschema"
	CreateCredDef     = VDROperationID + "/createcred-def"
	GetCredDef       = VDROperationID + "/getcred-def"
)

// provider contains dependencies for the common controller operations
// and is typically created by using aries.Context().
type provider interface {
	LIBVDRegistry() vdrapi.LibRegistry
}

// Operation contains basic common operations provided by controller REST API.
type Operation struct {
	handlers []rest.Handler
	command  *libvdr.Command
}

// New returns new common operations rest client instance.
func New(ctx provider) (*Operation, error) {
	cmd, err := libvdr.New(ctx)
	if err != nil {
		return nil, fmt.Errorf("new vdr : %w", err)
	}

	o := &Operation{command: cmd}
	o.registerHandler()

	return o, nil
}

// GetRESTHandlers get all controller API handler available for this service.
func (o *Operation) GetRESTHandlers() []rest.Handler {
	return o.handlers
}

// registerHandler register handlers to be exposed from this protocol service as REST API endpoints.
func (o *Operation) registerHandler() {
	// Add more protocol endpoints here to expose them as controller API endpoints
	o.handlers = []rest.Handler{

		cmdutil.NewHTTPHandler(CreateSchema, http.MethodPost, o.CreateSchema),
		cmdutil.NewHTTPHandler(Getschema, http.MethodGet, o.GetSchema),
		cmdutil.NewHTTPHandler(CreateCredDef, http.MethodPost, o.CreateCredDef),
		cmdutil.NewHTTPHandler(GetCredDef, http.MethodGet, o.GetCredDef),
	}
}

// CreateDID swagger:route POST /vdr/did/create vdr createDIDReq
//
// Create a did document.
//
// Responses:
//    default: genericError
//        200: documentRes
func (o *Operation) CreateSchema(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.CreateSchema, rw, req.Body)
}

func (o *Operation) GetSchema(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.GetSchema, rw, req.Body)
}

func (o *Operation) CreateCredDef(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.CreateCredDef, rw, req.Body)
}

func (o *Operation) GetCredDef(rw http.ResponseWriter, req *http.Request) {
	rest.Execute(o.command.GetCredDef, rw, req.Body)
}