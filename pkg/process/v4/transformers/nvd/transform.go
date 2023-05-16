package nvd

import (
	"fmt"

	"github.com/nextlinux/govulners-db/internal"
	"github.com/nextlinux/govulners-db/pkg/data"
	"github.com/nextlinux/govulners-db/pkg/process/v4/transformers"
	"github.com/nextlinux/govulners-db/pkg/provider/unmarshal"
	"github.com/nextlinux/govulners-db/pkg/provider/unmarshal/nvd"
	govulnersDB "github.com/nextlinux/govulners/govulners/db/v4"
	"github.com/nextlinux/govulners/govulners/db/v4/namespace"
)

const (
	// TODO: tech debt from a previous design
	feed  = "nvdv2"
	group = "nvdv2:cves"
)

func buildGovulnersNamespace(feed, group string) (namespace.Namespace, error) {
	if feed != "nvdv2" || group != "nvdv2:cves" {
		return nil, fmt.Errorf("invalid source for feed=%s, group=%s", feed, group)
	}

	ns, err := namespace.FromString("nvd:cpe")

	if err != nil {
		return nil, err
	}

	return ns, nil
}

func Transform(vulnerability unmarshal.NVDVulnerability) ([]data.Entry, error) {
	recordSource := fmt.Sprintf("%s:%s", feed, group)
	govulnersNamespace, err := buildGovulnersNamespace(feed, group)
	if err != nil {
		return nil, err
	}

	entryNamespace := govulnersNamespace.String()

	uniquePkgs := findUniquePkgs(vulnerability.Configurations...)

	// extract all links
	var links []string
	for _, externalRefs := range vulnerability.References {
		// TODO: should we capture other information here?
		if externalRefs.URL != "" {
			links = append(links, externalRefs.URL)
		}
	}

	// duplicate the vulnerabilities based on the set of unique packages the vulnerability is for
	var allVulns []govulnersDB.Vulnerability
	for _, p := range uniquePkgs.All() {
		matches := uniquePkgs.Matches(p)
		cpes := internal.NewStringSet()
		for _, m := range matches {
			cpes.Add(govulnersNamespace.Resolver().Normalize(m.Criteria))
		}

		// create vulnerability entry
		allVulns = append(allVulns, govulnersDB.Vulnerability{
			ID:                vulnerability.ID,
			VersionConstraint: buildConstraints(uniquePkgs.Matches(p)),
			VersionFormat:     "unknown",
			PackageName:       govulnersNamespace.Resolver().Normalize(p.Product),
			Namespace:         entryNamespace,
			CPEs:              cpes.ToSlice(),
			Fix: govulnersDB.Fix{
				State: govulnersDB.UnknownFixState,
			},
		})
	}

	// create vulnerability metadata entry (a single entry keyed off of the vulnerability ID)

	allCVSS := vulnerability.CVSS()
	metadata := govulnersDB.VulnerabilityMetadata{
		ID:           vulnerability.ID,
		DataSource:   "https://nvd.nist.gov/vuln/detail/" + vulnerability.ID,
		Namespace:    entryNamespace,
		RecordSource: recordSource,
		Severity:     nvd.CvssSummaries(allCVSS).Sorted().Severity(),
		URLs:         links,
		Description:  vulnerability.Description(),
		Cvss:         getCvss(allCVSS...),
	}

	return transformers.NewEntries(allVulns, metadata), nil
}

func getCvss(cvss ...nvd.CvssSummary) []govulnersDB.Cvss {
	var results []govulnersDB.Cvss
	for _, c := range cvss {
		results = append(results, govulnersDB.Cvss{
			Version: c.Version,
			Vector:  c.Vector,
			Metrics: govulnersDB.CvssMetrics{
				BaseScore:           c.BaseScore,
				ExploitabilityScore: c.ExploitabilityScore,
				ImpactScore:         c.ImpactScore,
			},
		})
	}
	return results
}
