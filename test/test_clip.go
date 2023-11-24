package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
)

func setLocalClip(s string) {
	var copyCmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		copyCmd = exec.Command("pbcopy")
	case "windows":
		copyCmd = exec.Command("powershell.exe", "-command", "$input | Set-Clipboard")
	default:
		fmt.Println("Unsupported OS")
		return
	}
	var stderr bytes.Buffer
	copyCmd.Stderr = &stderr
	in, err := copyCmd.StdinPipe()
	if err != nil {
		fmt.Println("Command error output stdinPipe:", copyCmd.Stderr)
		return
	}
	if err = copyCmd.Start(); err != nil {
		fmt.Println("Command error output start:", stderr.String())
		return
	}
	if _, err = in.Write([]byte(s)); err != nil {
		fmt.Println("Command error output write:", stderr.String())
		return
	}
	if err = in.Close(); err != nil {
		fmt.Println("Command error output close:", stderr.String())
		return
	}
	if err = copyCmd.Wait(); err != nil {
		fmt.Println("Command error output wait:", stderr.String())
		return
	}
	fmt.Println("Clipboard set successfully")
}

func main() {
	setLocalClip("haha")
}
