package alerts

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/google/uuid"
)

// Fingerprint implements the canonical dedup identity (docs/10 §17.4):
// hash(rule_id, resource_type, resource_id, dimension_subset). SHA-256 over a
// canonical, unambiguous encoding (fixed-length UUIDs, a length-prefixed
// dimension JSON) rendered as 64 hex characters (the alerts.fingerprint CHECK
// pins the length).
func Fingerprint(ruleID uuid.UUID, resourceType string, resourceID uuid.UUID, dimensionSubset []byte) string {
	if len(dimensionSubset) == 0 {
		dimensionSubset = []byte("{}")
	}
	h := sha256.New()
	h.Write([]byte(ruleID.String()))
	h.Write([]byte{0})
	h.Write([]byte(resourceType))
	h.Write([]byte{0})
	h.Write([]byte(resourceID.String()))
	h.Write([]byte{0})
	h.Write(dimensionSubset)
	return hex.EncodeToString(h.Sum(nil))
}
