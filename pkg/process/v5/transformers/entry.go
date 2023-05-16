package transformers

import (
	"github.com/anchore/govulners-db/pkg/data"
	govulnersDB "github.com/anchore/govulners/govulners/db/v5"
)

func NewEntries(vs []govulnersDB.Vulnerability, metadata govulnersDB.VulnerabilityMetadata) []data.Entry {
	entries := []data.Entry{
		{
			DBSchemaVersion: govulnersDB.SchemaVersion,
			Data:            metadata,
		},
	}
	for _, vuln := range vs {
		entries = append(entries, data.Entry{
			DBSchemaVersion: govulnersDB.SchemaVersion,
			Data:            vuln,
		})
	}
	return entries
}
