package matchexclusions

import (
	"github.com/anchore/govulners-db/pkg/data"
	"github.com/anchore/govulners-db/pkg/provider/unmarshal"
	govulnersDB "github.com/anchore/govulners/govulners/db/v5"
)

func Transform(matchExclusion unmarshal.MatchExclusion) ([]data.Entry, error) {
	exclusion := govulnersDB.VulnerabilityMatchExclusion{
		ID:            matchExclusion.ID,
		Constraints:   nil,
		Justification: matchExclusion.Justification,
	}

	for _, c := range matchExclusion.Constraints {
		constraint := &govulnersDB.VulnerabilityMatchExclusionConstraint{
			Vulnerability: govulnersDB.VulnerabilityExclusionConstraint{
				Namespace: c.Vulnerability.Namespace,
				FixState:  govulnersDB.FixState(c.Vulnerability.FixState),
			},
			Package: govulnersDB.PackageExclusionConstraint{
				Name:     c.Package.Name,
				Language: c.Package.Language,
				Type:     c.Package.Type,
				Version:  c.Package.Version,
				Location: c.Package.Location,
			},
		}

		exclusion.Constraints = append(exclusion.Constraints, *constraint)
	}

	entries := []data.Entry{
		{
			DBSchemaVersion: govulnersDB.SchemaVersion,
			Data:            exclusion,
		},
	}

	return entries, nil
}
