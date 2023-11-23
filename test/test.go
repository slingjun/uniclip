package main

import (
	"fmt"
	"os/exec"

	"github.com/saintfish/chardet"
	"golang.org/x/text/encoding/simplifiedchinese"
	"golang.org/x/text/transform"
)

func main() {
	cmd := exec.Command("powershell.exe", "-command", "Get-Clipboard")
	out, _ := cmd.Output()
	byteArray := []byte(out) // Replace qwith your byte array

	// 创建字符编码检测器
	detector := chardet.NewTextDetector()

	// 检测文本的字符编码
	result, _ := detector.DetectBest(out)
	// 输出检测结果
	fmt.Println("Detected Encoding:", result.Charset)

	// 创建 GB18030 解码器
	decoder := simplifiedchinese.GB18030.NewDecoder()

	// 将 GB18030 编码的字节切片转换为 UTF-8 编码的字节切片
	utf8Bytes, _, _ := transform.Bytes(decoder, out)

	// 将 UTF-8 编码的字节切片转换为字符串
	utf8String := string(utf8Bytes)

	// Convert the byte array to a rune array
	fmt.Printf(utf8String)
	runeArray := []rune(string(byteArray))
	fmt.Printf("Rune Array: %q\n", runeArray)
	// Print the rune array
	fmt.Printf("Rune Array: %s\n", string(runeArray))
}
