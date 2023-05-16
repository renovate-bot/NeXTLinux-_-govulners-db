package processors

import (
	"io"
	"strings"

	"github.com/nextlinux/govulners-db/internal/log"
	"github.com/nextlinux/govulners-db/pkg/data"
	"github.com/nextlinux/govulners-db/pkg/provider/unmarshal"
)

type nvdProcessor struct {
	transformer data.NVDTransformer
}

func NewNVDProcessor(transformer data.NVDTransformer) data.Processor {
	return &nvdProcessor{
		transformer: transformer,
	}
}

func (p nvdProcessor) Process(reader io.Reader) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.NvdVulnerabilityEntries(reader)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsEmpty() {
			log.Warn("dropping empty NVD entry")
			continue
		}

		transformedEntries, err := p.transformer(entry.Cve)
		if err != nil {
			return nil, err
		}

		results = append(results, transformedEntries...)
	}

	return results, nil
}

func (p nvdProcessor) IsSupported(schemaURL string) bool {
	matchesSchemaType := strings.Contains(schemaURL, "https://raw.githubusercontent.com/nextlinux/vunnel/main/schema/vulnerability/nvd/schema-")
	if !matchesSchemaType {
		return false
	}

	if !strings.HasSuffix(schemaURL, "schema-1.0.0.json") {
		log.WithFields("schema", schemaURL).Trace("unsupported NVD schema version")
		return false
	}

	return true
}
