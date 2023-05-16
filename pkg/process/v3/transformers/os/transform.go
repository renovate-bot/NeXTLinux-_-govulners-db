package os

import (
	"fmt"
	"strings"

	"github.com/nextlinux/govulners-db/pkg/data"
	"github.com/nextlinux/govulners-db/pkg/process/common"
	"github.com/nextlinux/govulners-db/pkg/process/v3/transformers"
	"github.com/nextlinux/govulners-db/pkg/provider/unmarshal"
	govulnersDB "github.com/nextlinux/govulners/govulners/db/v3"
)

const (
	// TODO: tech debt from a previous design
	feed = "vulnerabilities"
)

func Transform(vulnerability unmarshal.OSVulnerability) ([]data.Entry, error) {
	group := vulnerability.Vulnerability.NamespaceName

	var allVulns []govulnersDB.Vulnerability

	recordSource := govulnersDB.RecordSource(feed, group)
	entryNamespace, err := govulnersDB.NamespaceForFeedGroup(feed, group)
	if err != nil {
		return nil, err
	}

	vulnerability.Vulnerability.FixedIn = vulnerability.Vulnerability.FixedIn.FilterToHighestModularity()

	// there may be multiple packages indicated within the FixedIn field, we should make
	// separate vulnerability entries (one for each name|namespace combo) while merging
	// constraint ranges as they are found.
	for idx, fixedInEntry := range vulnerability.Vulnerability.FixedIn {
		// create vulnerability entry
		allVulns = append(allVulns, govulnersDB.Vulnerability{
			ID:                     vulnerability.Vulnerability.Name,
			VersionConstraint:      enforceConstraint(fixedInEntry.Version, fixedInEntry.VersionFormat),
			VersionFormat:          fixedInEntry.VersionFormat,
			PackageName:            fixedInEntry.Name,
			Namespace:              entryNamespace,
			RelatedVulnerabilities: getRelatedVulnerabilities(vulnerability),
			Fix:                    getFix(vulnerability, idx),
			Advisories:             getAdvisories(vulnerability, idx),
		})
	}

	// create vulnerability metadata entry (a single entry keyed off of the vulnerability ID)
	metadata := govulnersDB.VulnerabilityMetadata{
		ID:           vulnerability.Vulnerability.Name,
		Namespace:    entryNamespace,
		DataSource:   vulnerability.Vulnerability.Link,
		RecordSource: recordSource,
		Severity:     vulnerability.Vulnerability.Severity,
		URLs:         getLinks(vulnerability),
		Description:  vulnerability.Vulnerability.Description,
		Cvss:         getCvss(vulnerability),
	}

	return transformers.NewEntries(allVulns, metadata), nil
}

func getLinks(entry unmarshal.OSVulnerability) []string {
	// find all URLs related to the vulnerability
	links := []string{entry.Vulnerability.Link}
	if entry.Vulnerability.Metadata.CVE != nil {
		for _, cve := range entry.Vulnerability.Metadata.CVE {
			if cve.Link != "" {
				links = append(links, cve.Link)
			}
		}
	}
	return links
}

func getCvss(entry unmarshal.OSVulnerability) (cvss []govulnersDB.Cvss) {
	for _, vendorCvss := range entry.Vulnerability.CVSS {
		cvss = append(cvss, govulnersDB.Cvss{
			Version: vendorCvss.Version,
			Vector:  vendorCvss.VectorString,
			Metrics: govulnersDB.NewCvssMetrics(
				vendorCvss.BaseMetrics.BaseScore,
				vendorCvss.BaseMetrics.ExploitabilityScore,
				vendorCvss.BaseMetrics.ImpactScore,
			),
			VendorMetadata: transformers.VendorBaseMetrics{
				BaseSeverity: vendorCvss.BaseMetrics.BaseSeverity,
				Status:       vendorCvss.Status,
			},
		})
	}
	return cvss
}

func getAdvisories(entry unmarshal.OSVulnerability, idx int) (advisories []govulnersDB.Advisory) {
	fixedInEntry := entry.Vulnerability.FixedIn[idx]

	for _, advisory := range fixedInEntry.VendorAdvisory.AdvisorySummary {
		advisories = append(advisories, govulnersDB.Advisory{
			ID:   advisory.ID,
			Link: advisory.Link,
		})
	}
	return advisories
}

func getFix(entry unmarshal.OSVulnerability, idx int) govulnersDB.Fix {
	fixedInEntry := entry.Vulnerability.FixedIn[idx]

	var fixedInVersions []string
	fixedInVersion := common.CleanFixedInVersion(fixedInEntry.Version)
	if fixedInVersion != "" {
		fixedInVersions = append(fixedInVersions, fixedInVersion)
	}

	fixState := govulnersDB.NotFixedState
	if len(fixedInVersions) > 0 {
		fixState = govulnersDB.FixedState
	} else if fixedInEntry.VendorAdvisory.NoAdvisory {
		fixState = govulnersDB.WontFixState
	}

	return govulnersDB.Fix{
		Versions: fixedInVersions,
		State:    fixState,
	}
}

func getRelatedVulnerabilities(entry unmarshal.OSVulnerability) (vulns []govulnersDB.VulnerabilityReference) {
	// associate related vulnerabilities from the NVD namespace
	if strings.HasPrefix(entry.Vulnerability.Name, "CVE") {
		vulns = append(vulns, govulnersDB.VulnerabilityReference{
			ID:        entry.Vulnerability.Name,
			Namespace: govulnersDB.NVDNamespace,
		})
	}

	// note: an example of multiple CVEs for a record is centos:5 RHSA-2007:0055 which maps to CVE-2007-0002 and CVE-2007-1466
	for _, ref := range entry.Vulnerability.Metadata.CVE {
		vulns = append(vulns, govulnersDB.VulnerabilityReference{
			ID:        ref.Name,
			Namespace: govulnersDB.NVDNamespace,
		})
	}
	return vulns
}

func enforceConstraint(constraint, format string) string {
	constraint = common.CleanConstraint(constraint)
	if len(constraint) == 0 {
		return ""
	}
	switch strings.ToLower(format) {
	case "semver":
		return common.EnforceSemVerConstraint(constraint)
	default:
		// the passed constraint is a fixed version
		return fmt.Sprintf("< %s", constraint)
	}
}
