package processors

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nextlinux/govulners-db/pkg/data"
	testUtils "github.com/nextlinux/govulners-db/pkg/process/tests"
	"github.com/nextlinux/govulners-db/pkg/provider/unmarshal"
)

func mockOSProcessorTransform(vulnerability unmarshal.OSVulnerability) ([]data.Entry, error) {
	return []data.Entry{
		{
			DBSchemaVersion: 0,
			Data:            vulnerability,
		},
	}, nil
}

func TestOSProcessor_Process(t *testing.T) {
	f, err := os.Open("test-fixtures/os.json")
	require.NoError(t, err)
	defer testUtils.CloseFile(f)

	processor := NewOSProcessor(mockOSProcessorTransform)
	entries, err := processor.Process(f)

	require.NoError(t, err)
	assert.Len(t, entries, 4)
}
