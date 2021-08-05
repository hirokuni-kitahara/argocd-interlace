package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "argocd-interlace version",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("argocd-interlace 0.0.1")
	},
}
