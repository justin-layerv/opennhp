/*
 * Copyright (c) 2024 OpenNHP Authors. All Rights Reserved.
 *
 * This file is part of OpenNHP.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package server

import (
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// TestStampQurlV2RevocationMetadata_FromResourceData asserts the PRODUCTION
// res -> AOP mapping directly (the same helper processACOperation and the
// forward-path mock both call). Previously this mapping was only exercised
// through a live AC round-trip, so a field-copy bug or a mock/prod drift could
// slip through; this pins the populated fields field-for-field — including
// session_id, which the steady-state authorize (re-knock) path carries.
func TestStampQurlV2RevocationMetadata_FromResourceData(t *testing.T) {
	res := &common.ResourceData{
		QurlUserPublicKeyHash: "a1b2c3",
		ResourcePublicKeyHash: "d4e5f6",
		QurlSessionId:         "sess_live_1",
		AdmissionId:           "adm_test123",
		Deadline:              1781910300,
	}
	aop := &common.ServerACOpsMsg{UserId: "u"}

	stampQurlV2RevocationMetadata(aop, res)

	if aop.QurlUserPublicKeyHash != "a1b2c3" {
		t.Errorf("QurlUserPublicKeyHash = %q, want %q", aop.QurlUserPublicKeyHash, "a1b2c3")
	}
	if aop.ResourcePublicKeyHash != "d4e5f6" {
		t.Errorf("ResourcePublicKeyHash = %q, want %q", aop.ResourcePublicKeyHash, "d4e5f6")
	}
	if aop.QurlSessionId != "sess_live_1" {
		t.Errorf("QurlSessionId = %q, want %q (carried on the authorize/re-knock path)", aop.QurlSessionId, "sess_live_1")
	}
	if aop.AdmissionId != "adm_test123" {
		t.Errorf("AdmissionId = %q, want %q", aop.AdmissionId, "adm_test123")
	}
	if aop.Deadline != 1781910300 {
		t.Errorf("Deadline = %d, want %d", aop.Deadline, 1781910300)
	}
	// revocation_epoch is still not carried from ResourceData (no field on
	// ResourceData; no admission response returns it), so it must stay zero.
	if aop.RevocationEpoch != 0 {
		t.Errorf("RevocationEpoch must stay zero (not carried yet); got %d", aop.RevocationEpoch)
	}
}

// TestStampQurlV2RevocationMetadata_NilResource is the legacy/non-v2 path:
// res == nil leaves the AOP's qURL v2 fields untouched (zero), so a legacy
// admission stays byte-identical on the wire (the fields are omitempty).
func TestStampQurlV2RevocationMetadata_NilResource(t *testing.T) {
	aop := &common.ServerACOpsMsg{UserId: "u"}
	stampQurlV2RevocationMetadata(aop, nil)

	if aop.QurlUserPublicKeyHash != "" || aop.ResourcePublicKeyHash != "" ||
		aop.AdmissionId != "" || aop.Deadline != 0 ||
		aop.QurlSessionId != "" || aop.RevocationEpoch != 0 {
		t.Errorf("nil res must leave all qURL v2 AOP fields zero, got %#v", aop)
	}
}

// TestStampQurlV2RevocationMetadata_ResourceHashOnly covers a catalog-only
// ResourceData shape: a catalog ResourceData carries only
// resource_public_key_hash (the per-admission fields are absent), so only that
// one field is stamped. Upgraded native forwards overlay the narrow admission
// revocation sidecar before this helper runs; this test keeps the
// legacy/catalog-only behavior explicit.
func TestStampQurlV2RevocationMetadata_ResourceHashOnly(t *testing.T) {
	res := &common.ResourceData{ResourcePublicKeyHash: "catalog_hash"}
	aop := &common.ServerACOpsMsg{UserId: "u"}

	stampQurlV2RevocationMetadata(aop, res)

	if aop.ResourcePublicKeyHash != "catalog_hash" {
		t.Errorf("ResourcePublicKeyHash = %q, want %q", aop.ResourcePublicKeyHash, "catalog_hash")
	}
	if aop.QurlUserPublicKeyHash != "" || aop.AdmissionId != "" || aop.Deadline != 0 {
		t.Errorf("catalog-only path must omit per-admission fields; got user=%q adm=%q deadline=%d",
			aop.QurlUserPublicKeyHash, aop.AdmissionId, aop.Deadline)
	}
}
