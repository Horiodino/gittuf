// Copyright The gittuf Authors
// SPDX-License-Identifier: Apache-2.0

package rsl

import (
	"github.com/gittuf/gittuf/internal/cmd/rsl/annotate"
	"github.com/gittuf/gittuf/internal/cmd/rsl/log"
	"github.com/gittuf/gittuf/internal/cmd/rsl/propagate"
	"github.com/gittuf/gittuf/internal/cmd/rsl/record"
	"github.com/gittuf/gittuf/internal/cmd/rsl/remote"
	"github.com/gittuf/gittuf/internal/cmd/rsl/skiprewritten"
	"github.com/spf13/cobra"
)

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "rsl",
		Short:             "Tools to manage the repository's reference state log",
		DisableAutoGenTag: true,
	}

	cmd.AddCommand(annotate.New())
	cmd.AddCommand(log.New())
	cmd.AddCommand(propagate.New())
	cmd.AddCommand(record.New())
	cmd.AddCommand(remote.New())
	cmd.AddCommand(skiprewritten.New())

	return cmd
}
