package v3

import (
	"github.com/nextlinux/govulners-db/pkg/data"
	"github.com/nextlinux/govulners-db/pkg/process/processors"
	"github.com/nextlinux/govulners-db/pkg/process/v3/transformers/github"
	"github.com/nextlinux/govulners-db/pkg/process/v3/transformers/msrc"
	"github.com/nextlinux/govulners-db/pkg/process/v3/transformers/nvd"
	"github.com/nextlinux/govulners-db/pkg/process/v3/transformers/os"
)

func Processors() []data.Processor {
	return []data.Processor{
		processors.NewGitHubProcessor(github.Transform),
		processors.NewMSRCProcessor(msrc.Transform),
		processors.NewNVDProcessor(nvd.Transform),
		processors.NewOSProcessor(os.Transform),
	}
}
