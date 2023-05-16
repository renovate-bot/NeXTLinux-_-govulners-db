package msrc

import (
	"fmt"

	"github.com/nextlinux/govulners-db/pkg/data"
	"github.com/nextlinux/govulners-db/pkg/process/common"
	"github.com/nextlinux/govulners-db/pkg/process/v3/transformers"
	"github.com/nextlinux/govulners-db/pkg/provider/unmarshal"
	govulnersDB "github.com/nextlinux/govulners/govulners/db/v3"
)

const (
	// TODO: tech debt from a previous design
	feed        = "microsoft"
	groupPrefix = "msrc"
)

// Transform gets called by the parser, which consumes entries from the JSON files previously pulled. Each VulnDBVulnerability represents
// a single unmarshalled entry from the feed service
func Transform(vulnerability unmarshal.MSRCVulnerability) ([]data.Entry, error) {
	group := fmt.Sprintf("%s:%s", groupPrefix, vulnerability.Product.ID)
	recordSource := govulnersDB.RecordSource(feed, group)
	entryNamespace, err := govulnersDB.NamespaceForFeedGroup(feed, group)
	if err != nil {
		return nil, err
	}

	// In nextlinux-enterprise windows analyzer, "base" represents unpatched windows images (images with no KBs).
	// If a vulnerability exists for a Microsoft Product ID and the image has no KBs (which are patches),
	// then the image must be vulnerable to the image.
	//nolint:gocritic
	versionConstraint := append(vulnerability.Vulnerable, "base")

	allVulns := []govulnersDB.Vulnerability{
		{
			ID:                vulnerability.ID,
			VersionConstraint: common.OrConstraints(versionConstraint...),
			VersionFormat:     "kb",
			PackageName:       vulnerability.Product.ID,
			Namespace:         entryNamespace,
			Fix:               getFix(vulnerability),
		},
	}

	// create vulnerability metadata entry (a single entry keyed off of the vulnerability ID)
	metadata := govulnersDB.VulnerabilityMetadata{
		ID:           vulnerability.ID,
		DataSource:   vulnerability.Link,
		Namespace:    entryNamespace,
		RecordSource: recordSource,
		Severity:     vulnerability.Severity,
		URLs:         []string{vulnerability.Link},
		// There is no description for vulnerabilities from the feed service
		// summary gives something like "windows information disclosure vulnerability"
		//Description:  vulnerability.Summary,
		Cvss: []govulnersDB.Cvss{
			{
				Metrics: govulnersDB.CvssMetrics{BaseScore: vulnerability.Cvss.BaseScore},
				Vector:  vulnerability.Cvss.Vector,
			},
		},
	}

	return transformers.NewEntries(allVulns, metadata), nil
}

func getFix(entry unmarshal.MSRCVulnerability) govulnersDB.Fix {
	fixedInVersion := fixedInKB(entry)
	fixState := govulnersDB.FixedState

	if fixedInVersion == "" {
		fixState = govulnersDB.NotFixedState
	}

	return govulnersDB.Fix{
		Versions: []string{fixedInVersion},
		State:    fixState,
	}
}

// fixedInKB finds the "latest" patch (KB id) amongst the available microsoft patches and returns it
// if the "latest" patch cannot be found, an error is returned
func fixedInKB(vulnerability unmarshal.MSRCVulnerability) string {
	for _, fixedIn := range vulnerability.FixedIn {
		if fixedIn.IsLatest {
			return fixedIn.ID
		}
	}
	return ""
}
