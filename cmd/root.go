package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/gajananan/argocd-interlace/pkg/controller"
	"github.com/spf13/cobra"
)

var kubeconfig string
var namespace string
var debug bool

var rootCmd = &cobra.Command{
	Use:   "argocd-interlace",
	Short: "Kubernetes event collector and notifier",
	Long:  ``,
	Run: func(cmd *cobra.Command, args []string) {

		config, _ := cmd.Flags().GetString("kubeconfig")
		namespace, _ := cmd.Flags().GetString("namespace")
		debug, _ := cmd.Flags().GetBool("debug")

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go controller.Start(ctx, config, namespace, debug)

		// Wait forever
		select {}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	rootCmd.AddCommand(versionCmd)
	rootCmd.Flags().StringVarP(&kubeconfig, "kubeconfig", "k", "", "path to kubeconfig file")
	rootCmd.Flags().StringVarP(&namespace, "namespace", "n", "", "target argocd-namespace")
	rootCmd.Flags().BoolVarP(&debug, "debug", "d", false, "debug option")

}
