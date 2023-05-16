package v1

import (
	"github.com/nextlinux/govulners-db/pkg/data"
	"github.com/nextlinux/govulners-db/pkg/process/processors"
	"github.com/nextlinux/govulners-db/pkg/process/v1/transformers/github"
	"github.com/nextlinux/govulners-db/pkg/process/v1/transformers/nvd"
	"github.com/nextlinux/govulners-db/pkg/process/v1/transformers/os"
)

func Processors() []data.Processor {
	return []data.Processor{
		processors.NewGitHubProcessor(github.Transform),
		processors.NewNVDProcessor(nvd.Transform),
		processors.NewOSProcessor(os.Transform),
	}
}
