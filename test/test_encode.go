package main

import (
	"fmt"
	"os/exec"
	common "uniclip/Common"

	"golang.org/x/text/transform"
)

func main() {
	cmd := exec.Command("powershell.exe", "-command", "Get-Clipboard")
	out, _ := cmd.Output()
	result := common.GetBestCharset(out)
	fmt.Println("Original String: %q, Detected Encoding: %s,  Confidence: %d", out, result.Charset, result.Confidence)
	encoding_s := common.CvtEncoding(result.Charset)
	decoder := encoding_s.NewDecoder()
	utf8Bytes, _, _ := transform.Bytes(decoder, out)
	utf8String := string(utf8Bytes)

	fmt.Printf("String representation: %s\n", utf8String)
}
