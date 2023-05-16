package github

import (
	"github.com/nextlinux/govulners-db/pkg/data"
	"github.com/nextlinux/govulners-db/pkg/process/common"
	"github.com/nextlinux/govulners-db/pkg/process/v3/transformers"
	"github.com/nextlinux/govulners-db/pkg/provider/unmarshal"
	govulnersDB "github.com/nextlinux/govulners/govulners/db/v3"
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
	entryNamespace, err := govulnersDB.NamespaceForFeedGroup(feed, vulnerability.Advisory.Namespace)
	if err != nil {
		return nil, err
	}

	// there may be multiple packages indicated within the FixedIn field, we should make
	// separate vulnerability entries (one for each name|namespaces combo) while merging
	// constraint ranges as they are found.
	for idx, fixedInEntry := range vulnerability.Advisory.FixedIn {
		constraint := common.EnforceSemVerConstraint(fixedInEntry.Range)

		var versionFormat string
		switch vulnerability.Advisory.Namespace {
		case "github:python":
			versionFormat = "python"
		default:
			versionFormat = "unknown"
		}

		// create vulnerability entry
		allVulns = append(allVulns, govulnersDB.Vulnerability{
			ID:                     vulnerability.Advisory.GhsaID,
			VersionConstraint:      constraint,
			VersionFormat:          versionFormat,
			RelatedVulnerabilities: getRelatedVulnerabilities(vulnerability),
			PackageName:            fixedInEntry.Name,
			Namespace:              entryNamespace,
			Fix:                    getFix(vulnerability, idx),
		})
	}

	// create vulnerability metadata entry (a single entry keyed off of the vulnerability ID)
	metadata := govulnersDB.VulnerabilityMetadata{
		ID:           vulnerability.Advisory.GhsaID,
		DataSource:   vulnerability.Advisory.URL,
		Namespace:    entryNamespace,
		RecordSource: recordSource,
		Severity:     vulnerability.Advisory.Severity,
		URLs:         []string{vulnerability.Advisory.URL},
		Description:  vulnerability.Advisory.Summary,
	}

	return transformers.NewEntries(allVulns, metadata), nil
}

func getFix(entry unmarshal.GitHubAdvisory, idx int) govulnersDB.Fix {
	fixedInEntry := entry.Advisory.FixedIn[idx]

	var fixedInVersions []string
	fixedInVersion := common.CleanFixedInVersion(fixedInEntry.Identifier)
	if fixedInVersion != "" {
		fixedInVersions = append(fixedInVersions, fixedInVersion)
	}

	fixState := govulnersDB.NotFixedState
	if len(fixedInVersions) > 0 {
		fixState = govulnersDB.FixedState
	}

	return govulnersDB.Fix{
		Versions: fixedInVersions,
		State:    fixState,
	}
}

func getRelatedVulnerabilities(entry unmarshal.GitHubAdvisory) []govulnersDB.VulnerabilityReference {
	vulns := make([]govulnersDB.VulnerabilityReference, len(entry.Advisory.CVE))
	for idx, cve := range entry.Advisory.CVE {
		vulns[idx] = govulnersDB.VulnerabilityReference{
			ID:        cve,
			Namespace: govulnersDB.NVDNamespace,
		}
	}
	return vulns
}
