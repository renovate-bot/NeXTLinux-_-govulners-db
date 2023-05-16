package v5

import (
	"github.com/nextlinux/govulners-db/pkg/data"
	"github.com/nextlinux/govulners-db/pkg/process/processors"
	"github.com/nextlinux/govulners-db/pkg/process/v5/transformers/github"
	"github.com/nextlinux/govulners-db/pkg/process/v5/transformers/matchexclusions"
	"github.com/nextlinux/govulners-db/pkg/process/v5/transformers/msrc"
	"github.com/nextlinux/govulners-db/pkg/process/v5/transformers/nvd"
	"github.com/nextlinux/govulners-db/pkg/process/v5/transformers/os"
)

func Processors() []data.Processor {
	return []data.Processor{
		processors.NewGitHubProcessor(github.Transform),
		processors.NewMSRCProcessor(msrc.Transform),
		processors.NewNVDProcessor(nvd.Transform),
		processors.NewOSProcessor(os.Transform),
		processors.NewMatchExclusionProcessor(matchexclusions.Transform),
	}
}
