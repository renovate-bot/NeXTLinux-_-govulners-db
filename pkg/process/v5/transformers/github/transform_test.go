package github

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	testUtils "github.com/anchore/govulners-db/pkg/process/tests"
	"github.com/anchore/govulners-db/pkg/provider/unmarshal"
	govulnersDB "github.com/anchore/govulners/govulners/db/v5"
	"github.com/anchore/govulners/govulners/db/v5/namespace"
	"github.com/anchore/govulners/govulners/db/v5/namespace/language"
	syftPkg "github.com/anchore/syft/syft/pkg"
)

func TestBuildGovulnersNamespace(t *testing.T) {
	tests := []struct {
		group     string
		namespace namespace.Namespace
	}{
		{
			group:     "github:python",
			namespace: language.NewNamespace("github", syftPkg.Python, ""),
		},
		{
			group:     "github:composer",
			namespace: language.NewNamespace("github", syftPkg.PHP, ""),
		},
		{
			group:     "github:gem",
			namespace: language.NewNamespace("github", syftPkg.Ruby, ""),
		},
		{
			group:     "github:npm",
			namespace: language.NewNamespace("github", syftPkg.JavaScript, ""),
		},
		{
			group:     "github:go",
			namespace: language.NewNamespace("github", syftPkg.Go, ""),
		},
		{
			group:     "github:nuget",
			namespace: language.NewNamespace("github", syftPkg.Dotnet, ""),
		},
		{
			group:     "github:rust",
			namespace: language.NewNamespace("github", syftPkg.Rust, ""),
		},
	}

	for _, test := range tests {
		ns, err := buildGovulnersNamespace(test.group)

		assert.NoError(t, err)
		assert.Equal(t, test.namespace, ns)
	}
}

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
			ID:                "GHSA-p5wr-vp8g-q5p4",
			VersionConstraint: ">=4.0,<4.3.12",
			VersionFormat:     "python",
			RelatedVulnerabilities: []govulnersDB.VulnerabilityReference{
				{
					ID:        "CVE-2017-5524",
					Namespace: "nvd:cpe",
				},
			},
			PackageName: "plone",
			Namespace:   "github:language:python",
			Fix: govulnersDB.Fix{
				State:    govulnersDB.FixedState,
				Versions: []string{"4.3.12"},
			},
		},
		{
			ID:                "GHSA-p5wr-vp8g-q5p4",
			VersionConstraint: ">=5.1a1,<5.1b1",
			VersionFormat:     "python",
			RelatedVulnerabilities: []govulnersDB.VulnerabilityReference{
				{
					ID:        "CVE-2017-5524",
					Namespace: "nvd:cpe",
				},
			},
			PackageName: "plone",
			Namespace:   "github:language:python",
			Fix: govulnersDB.Fix{
				Versions: []string{"5.1b1"},
				State:    govulnersDB.FixedState,
			},
		},
		{
			ID:                "GHSA-p5wr-vp8g-q5p4",
			VersionConstraint: ">=5.0rc1,<5.0.7",
			VersionFormat:     "python",
			RelatedVulnerabilities: []govulnersDB.VulnerabilityReference{
				{
					ID:        "CVE-2017-5524",
					Namespace: "nvd:cpe",
				},
			},
			PackageName: "plone",
			Namespace:   "github:language:python",
			Fix: govulnersDB.Fix{
				Versions: []string{"5.0.7"},
				State:    govulnersDB.FixedState,
			},
		},
	}

	expectedMetadata := govulnersDB.VulnerabilityMetadata{
		ID:           "GHSA-p5wr-vp8g-q5p4",
		Namespace:    "github:language:python",
		RecordSource: "github:github:python",
		DataSource:   "https://github.com/advisories/GHSA-p5wr-vp8g-q5p4",
		Severity:     "Medium",
		URLs:         []string{"https://github.com/advisories/GHSA-p5wr-vp8g-q5p4"},
		Description:  "Moderate severity vulnerability that affects Plone",
	}

	f, err := os.Open("test-fixtures/github-github-python-1.json")
	require.NoError(t, err)
	defer testUtils.CloseFile(f)

	entries, err := unmarshal.GitHubAdvisoryEntries(f)
	require.NoError(t, err)

	require.Len(t, entries, 1)

	entry := entries[0]

	dataEntries, err := Transform(entry)
	require.NoError(t, err)

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

	if diff := cmp.Diff(expectedVulns, vulns); diff != "" {
		t.Errorf("vulnerabilities do not match (-want +got):\n%s", diff)
	}
}

func TestDefaultVersionFormatNpmGitHubEntry(t *testing.T) {
	expectedVuln := govulnersDB.Vulnerability{
		ID:                "GHSA-vc9j-fhvv-8vrf",
		VersionConstraint: "<=0.2.0-prerelease.20200709173451",
		VersionFormat:     "unknown", // TODO: this should reference a format, yes? (not a string)
		RelatedVulnerabilities: []govulnersDB.VulnerabilityReference{
			{
				ID:        "CVE-2020-14000",
				Namespace: "nvd:cpe",
			},
		},
		PackageName: "scratch-vm",
		Namespace:   "github:language:javascript",
		Fix: govulnersDB.Fix{
			Versions: []string{"0.2.0-prerelease.20200714185213"},
			State:    govulnersDB.FixedState,
		},
	}

	expectedMetadata := govulnersDB.VulnerabilityMetadata{
		ID:           "GHSA-vc9j-fhvv-8vrf",
		Namespace:    "github:language:javascript",
		RecordSource: "github:github:npm",
		DataSource:   "https://github.com/advisories/GHSA-vc9j-fhvv-8vrf",
		Severity:     "High",
		URLs:         []string{"https://github.com/advisories/GHSA-vc9j-fhvv-8vrf"},
		Description:  "Remote Code Execution in scratch-vm",
	}

	f, err := os.Open("test-fixtures/github-github-npm-0.json")
	require.NoError(t, err)
	defer testUtils.CloseFile(f)

	entries, err := unmarshal.GitHubAdvisoryEntries(f)
	require.NoError(t, err)

	require.Len(t, entries, 1)

	entry := entries[0]

	dataEntries, err := Transform(entry)
	assert.NoError(t, err)

	for _, entry := range dataEntries {
		switch vuln := entry.Data.(type) {
		case govulnersDB.Vulnerability:
			assert.Equal(t, expectedVuln, vuln)
		case govulnersDB.VulnerabilityMetadata:
			assert.Equal(t, expectedMetadata, vuln)
		default:
			t.Fatalf("unexpected condition: data entry does not have a vulnerability or a metadata")
		}
	}

	// check vulnerability
	assert.Len(t, dataEntries, 2)
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
