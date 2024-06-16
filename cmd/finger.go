/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// fingerCmd represents the finger command
var fingerCmd = &cobra.Command{
	Use:   "finger",
	Short: "Fingerprinting of targets",
	Long:  "单独使用Milkyway的指纹识别功能",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("finger called")
	},
}

func init() {
	rootCmd.AddCommand(fingerCmd)
}
