package v2

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/anchore/govulners-db/pkg/data"
	govulnersDB "github.com/anchore/govulners/govulners/db/v2"
)

var _ govulnersDB.VulnerabilityMetadataStoreReader = (*mockReader)(nil)

type mockReader struct {
	metadata *govulnersDB.VulnerabilityMetadata
	err      error
}

func newMockReader(sev string) *mockReader {
	return &mockReader{
		metadata: &govulnersDB.VulnerabilityMetadata{
			Severity:     sev,
			RecordSource: "nvdv2:cves",
		},
	}
}

func newDeadMockReader() *mockReader {
	return &mockReader{
		err: errors.New("dead"),
	}
}

func (m mockReader) GetVulnerabilityMetadata(_, _ string) (*govulnersDB.VulnerabilityMetadata, error) {
	return m.metadata, m.err
}

func (m mockReader) GetAllVulnerabilityMetadata() (*[]govulnersDB.VulnerabilityMetadata, error) {
	panic("implement me")
}

func Test_normalizeSeverity(t *testing.T) {

	tests := []struct {
		name            string
		initialSeverity string
		recordSource    string
		cveID           string
		reader          govulnersDB.VulnerabilityMetadataStoreReader
		expected        data.Severity
	}{
		{
			name:            "skip missing metadata",
			initialSeverity: "",
			recordSource:    "test",
			reader:          &mockReader{},
			expected:        "",
		},
		{
			name:            "skip non-cve records metadata",
			cveID:           "GHSA-1234-1234-1234",
			initialSeverity: "",
			recordSource:    "test",
			reader:          newDeadMockReader(), // should not be used
			expected:        "",
		},
		{
			name:            "override empty severity",
			initialSeverity: "",
			recordSource:    "test",
			reader:          newMockReader("low"),
			expected:        data.SeverityLow,
		},
		{
			name:            "override unknown severity",
			initialSeverity: "unknown",
			recordSource:    "test",
			reader:          newMockReader("low"),
			expected:        data.SeverityLow,
		},
		{
			name:            "ignore record with severity already set",
			initialSeverity: "Low",
			recordSource:    "test",
			reader:          newMockReader("critical"), // should not be used
			expected:        data.SeverityLow,
		},
		{
			name:            "ignore nvd records",
			initialSeverity: "Low",
			recordSource:    "nvdv2:cves",
			reader:          newDeadMockReader(), // should not be used
			expected:        data.SeverityLow,
		},
		{
			name:            "db errors should not fail or modify the record",
			initialSeverity: "",
			recordSource:    "test",
			reader:          newDeadMockReader(),
			expected:        "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := &govulnersDB.VulnerabilityMetadata{
				ID:           "cve-2020-0000",
				Severity:     tt.initialSeverity,
				RecordSource: tt.recordSource,
			}
			if tt.cveID != "" {
				record.ID = tt.cveID
			}
			normalizeSeverity(record, tt.reader)
			assert.Equal(t, string(tt.expected), record.Severity)
		})
	}
}
