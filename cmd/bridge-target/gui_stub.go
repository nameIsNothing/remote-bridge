//go:build !windows

package main

import "fmt"

func runGUI(args []string) int {
	fmt.Println("图形界面目前仅支持 Windows；可使用 bridge-target ssh。")
	return 2
}
func attachTargetConsole() {}
