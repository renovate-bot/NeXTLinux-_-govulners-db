//nolint:dupl
package processors

import (
	"io"
	"strings"

	"github.com/nextlinux/govulners-db/internal/log"
	"github.com/nextlinux/govulners-db/pkg/data"
	"github.com/nextlinux/govulners-db/pkg/provider/unmarshal"
)

type githubProcessor struct {
	transformer data.GitHubTransformer
}

func NewGitHubProcessor(transformer data.GitHubTransformer) data.Processor {
	return &githubProcessor{
		transformer: transformer,
	}
}

func (p githubProcessor) Process(reader io.Reader) ([]data.Entry, error) {
	var results []data.Entry

	entries, err := unmarshal.GitHubAdvisoryEntries(reader)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsEmpty() {
			log.Warn("dropping empty GHSA entry")
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

func (p githubProcessor) IsSupported(schemaURL string) bool {
	matchesSchemaType := strings.Contains(schemaURL, "https://raw.githubusercontent.com/nextlinux/vunnel/main/schema/vulnerability/github-security-advisory/schema-")
	if !matchesSchemaType {
		return false
	}

	if !strings.HasSuffix(schemaURL, "schema-1.0.0.json") {
		log.WithFields("schema", schemaURL).Trace("unsupported GHSA schema version")
		return false
	}

	return true
}
