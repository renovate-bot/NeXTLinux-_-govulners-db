package github

import (
	"github.com/nextlinux/govulners-db/pkg/data"
	"github.com/nextlinux/govulners-db/pkg/process/common"
	"github.com/nextlinux/govulners-db/pkg/process/v2/transformers"
	"github.com/nextlinux/govulners-db/pkg/provider/unmarshal"
	govulnersDB "github.com/nextlinux/govulners/govulners/db/v2"
)

const (
	// TODO: tech debt from a previous design
	feed = "github"
)

func Transform(vulnerability unmarshal.GitHubAdvisory) ([]data.Entry, error) {
	var allVulns []govulnersDB.Vulnerability

	// Exclude entries marked as withdrawn
	if vulnerability.Advisory.Withdrawn != nil {
		return nil, nil
	}

	recordSource := govulnersDB.RecordSource(feed, vulnerability.Advisory.Namespace)

	// there may be multiple packages indicated within the FixedIn field, we should make
	// separate vulnerability entries (one for each name|namespace combo) while merging
	// constraint ranges as they are found.
	for _, advisory := range vulnerability.Advisory.FixedIn {
		constraint := common.EnforceSemVerConstraint(advisory.Range)

		var versionFormat string
		switch vulnerability.Advisory.Namespace {
		case "github:python":
			versionFormat = "python"
		default:
			versionFormat = "unknown"
		}

		// create vulnerability entry
		vuln := govulnersDB.Vulnerability{
			ID:                   vulnerability.Advisory.GhsaID,
			RecordSource:         recordSource,
			VersionConstraint:    constraint,
			VersionFormat:        versionFormat, // TODO: this should reference a format, yes? (not a string)
			ProxyVulnerabilities: vulnerability.Advisory.CVE,
			PackageName:          advisory.Name,
			Namespace:            advisory.Namespace,
			FixedInVersion:       common.CleanFixedInVersion(advisory.Identifier),
		}

		allVulns = append(allVulns, vuln)
	}

	// create vulnerability metadata entry (a single entry keyed off of the vulnerability ID)
	metadata := govulnersDB.VulnerabilityMetadata{
		ID:           vulnerability.Advisory.GhsaID,
		RecordSource: recordSource,
		Severity:     vulnerability.Advisory.Severity,
		Links:        []string{vulnerability.Advisory.URL},
		Description:  vulnerability.Advisory.Summary,
	}

	return transformers.NewEntries(allVulns, metadata), nil
}
