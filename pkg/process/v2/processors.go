package v2

import (
	"github.com/anchore/govulners-db/pkg/data"
	"github.com/anchore/govulners-db/pkg/process/processors"
	"github.com/anchore/govulners-db/pkg/process/v2/transformers/github"
	"github.com/anchore/govulners-db/pkg/process/v2/transformers/nvd"
	"github.com/anchore/govulners-db/pkg/process/v2/transformers/os"
)

func Processors() []data.Processor {
	return []data.Processor{
		processors.NewGitHubProcessor(github.Transform),
		processors.NewNVDProcessor(nvd.Transform),
		processors.NewOSProcessor(os.Transform),
	}
}
