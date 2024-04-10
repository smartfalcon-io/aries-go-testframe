/*
Copyright SecureKey Technologies Inc. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package libvdr

import (
	"github.com/hyperledger/aries-framework-go/component/libindy_vdr/api"
)

// ErrNotFound is returned when a DID resolver does not find the DID.
var ErrNotFound = api.ErrNotFound

// Registry vdr registry.
type Registry = api.Registry

// VDR verifiable data registry interface.
// TODO https://github.com/hyperledger/aries-framework-go/issues/2475
type Libvdr = api.Libvdr