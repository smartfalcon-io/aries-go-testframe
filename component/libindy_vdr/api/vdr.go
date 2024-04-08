/*
Copyright SecureKey Technologies Inc. All Rights Reserved.
Copyright Gen Digital Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package api

import (
	"errors"

)

// ErrNotFound is returned when a DID resolver does not find the DID.
var ErrNotFound = errors.New("Unable to Create Schema")

// const (
// 	// DIDCommServiceType default DID Communication service endpoint type.
// 	DIDCommServiceType = "did-communication"

// 	// DIDCommV2ServiceType is the DID Communications V2 service type.
// 	DIDCommV2ServiceType = "DIDCommMessaging"

// 	// LegacyServiceType is the DID Communication V1 indy based service type.
// 	LegacyServiceType = "IndyAgent"
// )

// Registry vdr registry.
type Registry interface {
	Read(schemaid string,genesis string) (string,error)
	Create(trusteeseed string, schema interface{}, genesis string) (string, error)
	Close() error
}

// VDR verifiable data registry interface.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2475
type Libvdr interface {
	Read(schemaid string,genesis string) (string,error)
	Create(trusteeseed string, schema interface{}, genesis string) (string, error)
	Close() error
}