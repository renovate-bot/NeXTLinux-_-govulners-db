package os

import (
	"fmt"
	"strings"

	"github.com/anchore/govulners-db/pkg/data"
	"github.com/anchore/govulners-db/pkg/process/common"
	"github.com/anchore/govulners-db/pkg/process/v2/transformers"
	"github.com/anchore/govulners-db/pkg/provider/unmarshal"
	govulnersDB "github.com/anchore/govulners/govulners/db/v2"
)

const (
	// TODO: tech debt from a previous design
	feed = "vulnerabilities"
)

func Transform(vulnerability unmarshal.OSVulnerability) ([]data.Entry, error) {
	group := vulnerability.Vulnerability.NamespaceName

	var allVulns []govulnersDB.Vulnerability

	recordSource := govulnersDB.RecordSource(feed, group)
	vulnerability.Vulnerability.FixedIn = vulnerability.Vulnerability.FixedIn.FilterToHighestModularity()

	// there may be multiple packages indicated within the FixedIn field, we should make
	// separate vulnerability entries (one for each name|namespace combo) while merging
	// constraint ranges as they are found.
	for _, advisory := range vulnerability.Vulnerability.FixedIn {
		// create vulnerability entry
		vuln := govulnersDB.Vulnerability{
			ID:                   vulnerability.Vulnerability.Name,
			RecordSource:         recordSource,
			VersionConstraint:    enforceConstraint(advisory.Version, advisory.VersionFormat),
			VersionFormat:        advisory.VersionFormat,
			PackageName:          advisory.Name,
			Namespace:            advisory.NamespaceName,
			ProxyVulnerabilities: []string{},
			FixedInVersion:       common.CleanFixedInVersion(advisory.Version),
		}

		// associate related vulnerabilities
		// note: an example of multiple CVEs for a record is centos:5 RHSA-2007:0055 which maps to CVE-2007-0002 and CVE-2007-1466
		for _, ref := range vulnerability.Vulnerability.Metadata.CVE {
			vuln.ProxyVulnerabilities = append(vuln.ProxyVulnerabilities, ref.Name)
		}

		allVulns = append(allVulns, vuln)
	}

	var cvssV2 *govulnersDB.Cvss
	if vulnerability.Vulnerability.Metadata.NVD.CVSSv2.Vectors != "" {
		cvssV2 = &govulnersDB.Cvss{
			BaseScore:           vulnerability.Vulnerability.Metadata.NVD.CVSSv2.Score,
			ExploitabilityScore: 0,
			ImpactScore:         0,
			Vector:              vulnerability.Vulnerability.Metadata.NVD.CVSSv2.Vectors,
		}
	}

	// find all URLs related to the vulnerability
	links := []string{vulnerability.Vulnerability.Link}
	if vulnerability.Vulnerability.Metadata.CVE != nil {
		for _, cve := range vulnerability.Vulnerability.Metadata.CVE {
			if cve.Link != "" {
				links = append(links, cve.Link)
			}
		}
	}

	// create vulnerability metadata entry (a single entry keyed off of the vulnerability ID)
	metadata := govulnersDB.VulnerabilityMetadata{
		ID:           vulnerability.Vulnerability.Name,
		RecordSource: recordSource,
		Severity:     vulnerability.Vulnerability.Severity,
		Links:        links,
		Description:  vulnerability.Vulnerability.Description,
		CvssV2:       cvssV2,
	}

	return transformers.NewEntries(allVulns, metadata), nil
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
