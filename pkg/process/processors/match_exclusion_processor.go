//nolint:dupl
package processors

import (
	"io"
	"strings"

	"github.com/nextlinux/govulners-db/internal/log"
	"github.com/nextlinux/govulners-db/pkg/data"
	"github.com/nextlinux/govulners-db/pkg/provider/unmarshal"
)

type matchExclusionProcessor struct {
	transformer data.MatchExclusionTransformer
}

func NewMatchExclusionProcessor(transformer data.MatchExclusionTransformer) data.Processor {
	return &matchExclusionProcessor{
		transformer: transformer,
	}
}

func (p matchExclusionProcessor) Process(reader io.Reader) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.MatchExclusions(reader)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsEmpty() {
			log.Warn("dropping empty match-exclusion entry")
			continue
		}

		transformedEntries, err := p.transformer(entry)
		if err != nil {
			return nil, err
		}

		results = append(results, transformedEntries...)
	}

	return results, nil
}

func (p matchExclusionProcessor) IsSupported(schemaURL string) bool {
	matchesSchemaType := strings.Contains(schemaURL, "https://raw.githubusercontent.com/nextlinux/vunnel/main/schema/match-exclusion/schema-")
	if !matchesSchemaType {
		return false
	}

	if !strings.HasSuffix(schemaURL, "schema-1.0.0.json") {
		log.WithFields("schema", schemaURL).Trace("unsupported match-exclusion schema version")
		return false
	}

	return true
}
