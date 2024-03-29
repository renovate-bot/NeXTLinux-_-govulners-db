package github

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	testUtils "github.com/nextlinux/govulners-db/pkg/process/tests"
	"github.com/nextlinux/govulners-db/pkg/provider/unmarshal"
	govulnersDB "github.com/nextlinux/govulners/govulners/db/v1"
)

func TestUnmarshalGitHubEntries(t *testing.T) {
	f, err := os.Open("test-fixtures/github-github-python-0.json")
	require.NoError(t, err)
	defer testUtils.CloseFile(f)

	entries, err := unmarshal.GitHubAdvisoryEntries(f)
	require.NoError(t, err)

	assert.Len(t, entries, 2)
}

func TestParseGitHubEntry(t *testing.T) {
	expectedVulns := []govulnersDB.Vulnerability{
		{
			ID:                   "GHSA-p5wr-vp8g-q5p4",
			RecordSource:         "github:python",
			VersionConstraint:    ">=4.0,<4.3.12",
			VersionFormat:        "python", // TODO: this should reference a format, yes? (not a string)
			ProxyVulnerabilities: []string{"CVE-2017-5524"},
			PackageName:          "Plone",
			Namespace:            "github:python",
			FixedInVersion:       "4.3.12",
		},
		{
			ID:                   "GHSA-p5wr-vp8g-q5p4",
			RecordSource:         "github:python",
			VersionConstraint:    ">=5.1a1,<5.1b1",
			VersionFormat:        "python", // TODO: this should reference a format, yes? (not a string)
			ProxyVulnerabilities: []string{"CVE-2017-5524"},
			PackageName:          "Plone",
			Namespace:            "github:python",
			FixedInVersion:       "5.1b1",
		},
		{
			ID:                   "GHSA-p5wr-vp8g-q5p4",
			RecordSource:         "github:python",
			VersionConstraint:    ">=5.0rc1,<5.0.7",
			VersionFormat:        "python", // TODO: this should reference a format, yes? (not a string)
			ProxyVulnerabilities: []string{"CVE-2017-5524"},
			PackageName:          "Plone",
			Namespace:            "github:python",
			FixedInVersion:       "5.0.7",
		},
	}

	expectedMetadata := govulnersDB.VulnerabilityMetadata{
		ID:           "GHSA-p5wr-vp8g-q5p4",
		RecordSource: "github:python",
		Severity:     "Medium",
		Links:        []string{"https://github.com/advisories/GHSA-p5wr-vp8g-q5p4"},
		Description:  "Moderate severity vulnerability that affects Plone",
	}

	f, err := os.Open("test-fixtures/github-github-python-1.json")
	require.NoError(t, err)
	defer testUtils.CloseFile(f)

	entries, err := unmarshal.GitHubAdvisoryEntries(f)
	assert.NoError(t, err)
	assert.Len(t, entries, 1)

	entry := entries[0]

	dataEntries, err := Transform(entry)
	assert.NoError(t, err)

	var vulns []govulnersDB.Vulnerability
	for _, entry := range dataEntries {
		switch vuln := entry.Data.(type) {
		case govulnersDB.Vulnerability:
			vulns = append(vulns, vuln)
		case govulnersDB.VulnerabilityMetadata:
			assert.Equal(t, expectedMetadata, vuln)
		default:
			t.Fatalf("unexpected condition: data entry does not have a vulnerability or a metadata")
		}
	}

	// check vulnerability
	assert.Len(t, vulns, len(expectedVulns))

	assert.ElementsMatch(t, expectedVulns, vulns)

}

func TestDefaultVersionFormatNpmGitHubEntry(t *testing.T) {
	expectedVulns := []govulnersDB.Vulnerability{
		{
			ID:                   "GHSA-vc9j-fhvv-8vrf",
			RecordSource:         "github:npm",
			VersionConstraint:    "<=0.2.0-prerelease.20200709173451",
			VersionFormat:        "unknown", // TODO: this should reference a format, yes? (not a string)
			ProxyVulnerabilities: []string{"CVE-2020-14000"},
			PackageName:          "scratch-vm",
			Namespace:            "github:npm",
			FixedInVersion:       "0.2.0-prerelease.20200714185213",
		},
	}

	expectedMetadata := govulnersDB.VulnerabilityMetadata{
		ID:           "GHSA-vc9j-fhvv-8vrf",
		RecordSource: "github:npm",
		Severity:     "High",
		Links:        []string{"https://github.com/advisories/GHSA-vc9j-fhvv-8vrf"},
		Description:  "Remote Code Execution in scratch-vm",
	}

	f, err := os.Open("test-fixtures/github-github-npm-0.json")
	require.NoError(t, err)
	defer testUtils.CloseFile(f)

	entries, err := unmarshal.GitHubAdvisoryEntries(f)
	assert.NoError(t, err)
	assert.Len(t, entries, 1)

	entry := entries[0]

	dataEntries, err := Transform(entry)
	assert.NoError(t, err)

	var vulns []govulnersDB.Vulnerability
	for _, entry := range dataEntries {
		switch vuln := entry.Data.(type) {
		case govulnersDB.Vulnerability:
			vulns = append(vulns, vuln)
		case govulnersDB.VulnerabilityMetadata:
			assert.Equal(t, expectedMetadata, vuln)
		default:
			t.Fatalf("unexpected condition: data entry does not have a vulnerability or a metadata")
		}
	}

	// check vulnerability
	assert.Len(t, vulns, len(expectedVulns))

	assert.ElementsMatch(t, expectedVulns, vulns)
}

func TestFilterWithdrawnEntries(t *testing.T) {
	f, err := os.Open("test-fixtures/github-withdrawn.json")
	require.NoError(t, err)
	defer testUtils.CloseFile(f)

	entries, err := unmarshal.GitHubAdvisoryEntries(f)
	require.NoError(t, err)

	require.Len(t, entries, 1)

	entry := entries[0]

	dataEntries, err := Transform(entry)
	assert.NoError(t, err)
	assert.Nil(t, dataEntries)
}
