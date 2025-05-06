package main

import "github.com/o4f6bgpac3/template/cmd"

func main() {
	cmd.GetStaticFS = GetStaticFS

	cmd.Execute()
}
