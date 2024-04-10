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
	CreateSchema     = VDROperationID + "/create"
)

// provider contains dependencies for the common controller operations
// and is typically created by using aries.Context().
type provider interface {
	VDRegistry() vdrapi.Registry
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