package github

import (
	"fmt"
	"strings"

	"github.com/nextlinux/govulners-db/pkg/data"
	"github.com/nextlinux/govulners-db/pkg/process/common"
	"github.com/nextlinux/govulners-db/pkg/process/v4/transformers"
	"github.com/nextlinux/govulners-db/pkg/provider/unmarshal"
	govulnersDB "github.com/nextlinux/govulners/govulners/db/v4"
	"github.com/nextlinux/govulners/govulners/db/v4/namespace"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

const (
	// TODO: tech debt from a previous design
	feed = "github"
)

func buildGovulnersNamespace(feed, group string) (namespace.Namespace, error) {
	if feed != "github" {
		return nil, fmt.Errorf("unable to determine govulners namespace for enterprise feed=%s, group=%s", feed, group)
	}

	feedGroupComponents := strings.Split(group, ":")

	if len(feedGroupComponents) < 2 {
		return nil, fmt.Errorf("unable to determine govulners namespace for enterprise feed=%s, group=%s", feed, group)
	}

	feedGroupLang := feedGroupComponents[1]
	syftLanguage := syftPkg.LanguageByName(feedGroupLang)

	if syftLanguage == syftPkg.UnknownLanguage {
		// For now map nuget to dotnet as the language.
		if feedGroupLang == "nuget" {
			syftLanguage = syftPkg.Dotnet
		} else {
			return nil, fmt.Errorf("unable to determine govulners namespace for enterprise feed=%s, group=%s", feed, group)
		}
	}

	ns, err := namespace.FromString(fmt.Sprintf("github:language:%s", string(syftLanguage)))

	if err != nil {
		return nil, err
	}

	return ns, nil
}

func Transform(vulnerability unmarshal.GitHubAdvisory) ([]data.Entry, error) {
	var allVulns []govulnersDB.Vulnerability

	// Exclude entries marked as withdrawn
	if vulnerability.Advisory.Withdrawn != nil {
		return nil, nil
	}

	recordSource := fmt.Sprintf("%s:%s", feed, vulnerability.Advisory.Namespace)
	govulnersNamespace, err := buildGovulnersNamespace(feed, vulnerability.Advisory.Namespace)
	if err != nil {
		return nil, err
	}

	entryNamespace := govulnersNamespace.String()

	// there may be multiple packages indicated within the FixedIn field, we should make
	// separate vulnerability entries (one for each name|namespaces combo) while merging
	// constraint ranges as they are found.
	for idx, fixedInEntry := range vulnerability.Advisory.FixedIn {
		constraint := common.EnforceSemVerConstraint(fixedInEntry.Range)

		var versionFormat string
		switch entryNamespace {
		case "github:language:python":
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
			PackageName:            govulnersNamespace.Resolver().Normalize(fixedInEntry.Name),
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
			Namespace: "nvd:cpe",
		}
	}
	return vulns
}
