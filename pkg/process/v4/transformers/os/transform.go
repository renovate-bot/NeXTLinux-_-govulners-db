package os

import (
	"fmt"
	"strings"

	"github.com/anchore/govulners-db/pkg/data"
	"github.com/anchore/govulners-db/pkg/process/common"
	"github.com/anchore/govulners-db/pkg/process/v4/transformers"
	"github.com/anchore/govulners-db/pkg/provider/unmarshal"
	govulnersDB "github.com/anchore/govulners/govulners/db/v4"
	"github.com/anchore/govulners/govulners/db/v4/namespace"
	"github.com/anchore/govulners/govulners/distro"
)

const (
	// TODO: tech debt from a previous design
	feed = "vulnerabilities"
)

func Transform(vulnerability unmarshal.OSVulnerability) ([]data.Entry, error) {
	group := vulnerability.Vulnerability.NamespaceName

	var allVulns []govulnersDB.Vulnerability

	recordSource := fmt.Sprintf("%s:%s", feed, group)
	govulnersNamespace, err := buildGovulnersNamespace(feed, group)
	if err != nil {
		return nil, err
	}

	entryNamespace := govulnersNamespace.String()
	vulnerability.Vulnerability.FixedIn = vulnerability.Vulnerability.FixedIn.FilterToHighestModularity()

	for idx, fixedInEntry := range vulnerability.Vulnerability.FixedIn {
		// create vulnerability entry
		allVulns = append(allVulns, govulnersDB.Vulnerability{
			ID:                     vulnerability.Vulnerability.Name,
			VersionConstraint:      enforceConstraint(fixedInEntry.Version, fixedInEntry.VersionFormat),
			VersionFormat:          fixedInEntry.VersionFormat,
			PackageName:            govulnersNamespace.Resolver().Normalize(fixedInEntry.Name),
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

func buildGovulnersNamespace(feed, group string) (namespace.Namespace, error) {
	if feed != "vulnerabilities" {
		return nil, fmt.Errorf("unable to determine govulners namespace for enterprise feed=%s, group=%s", feed, group)
	}

	feedGroupComponents := strings.Split(group, ":")

	if len(feedGroupComponents) < 2 {
		return nil, fmt.Errorf("unable to determine govulners namespace for enterprise feed=%s, group=%s", feed, group)
	}

	// Currently known enterprise feed groups are expected to be of the form {distroID}:{version}
	feedGroupDistroID := feedGroupComponents[0]
	d, ok := distro.IDMapping[feedGroupDistroID]
	if !ok {
		return nil, fmt.Errorf("unable to determine govulners namespace for enterprise feed=%s, group=%s", feed, group)
	}

	providerName := d.String()

	switch d {
	case distro.OracleLinux:
		providerName = "oracle"
	case distro.AmazonLinux:
		providerName = "amazon"
	}

	ns, err := namespace.FromString(fmt.Sprintf("%s:distro:%s:%s", providerName, d.String(), feedGroupComponents[1]))

	if err != nil {
		return nil, err
	}

	return ns, nil
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
			Namespace: "nvd:cpe",
		})
	}

	// note: an example of multiple CVEs for a record is centos:5 RHSA-2007:0055 which maps to CVE-2007-0002 and CVE-2007-1466
	for _, ref := range entry.Vulnerability.Metadata.CVE {
		vulns = append(vulns, govulnersDB.VulnerabilityReference{
			ID:        ref.Name,
			Namespace: "nvd:cpe",
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
