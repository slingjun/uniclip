package main

import (
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	common "uniclip/Common"

	"github.com/jessevdk/go-flags" // go-flags
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh/terminal"
	"golang.org/x/text/transform"
)

var (
	secondsBetweenChecksForClipChange = 1
	helpMsg                           = `Uniclip - Universal Clipboard
With Uniclip, you can copy from one device and paste on another.

Usage: uniclip [--secure/-s] [--debug/-d] [ <address> | --help/-h ]
Examples:
   uniclip                                   # start a new clipboard
   uniclip 192.168.86.24:53701               # join the clipboard at 192.168.86.24:53701
   uniclip -d                                # start a new clipboard with debug output
   uniclip -d --secure 192.168.86.24:53701   # join the clipboard with debug output and enable encryption
Running just ` + "`uniclip`" + ` will start a new clipboard.
It will also provide an address with which you can connect to the same clipboard with another device.
Refer to https://github.com/quackduck/uniclip for more information`
	listOfClients  = make([]*bufio.Writer, 0)
	localClipboard string
	printDebugInfo = false
	version        = "dev"
	cryptoStrength = 16384
	secure         = false
	password       []byte
)

type Option struct {
	Version bool   `short:"v" long:"version" description:"Show version message"`
	Port    int    `short:"p" long:"port" description:"Setup port"`
	Debug   bool   `short:"d" long:"debug" description:"Setup debug mode"`
	Help    bool   `short:"h" long:"help" description:"Show help message"`
	Secure  bool   `short:"s" long:"secure" description:"Setup Secure Mode"`
	Connect string `short:"c" long:"connect" description:"Server ip"`
}

// NewSomething create new instance of Something
func GetDefaultOption() Option {
	opt := Option{}
	opt.Port = -1
	opt.Connect = ""
	opt.Version = false
	opt.Debug = false
	opt.Help = false
	opt.Secure = false
	return opt
}

// TODO: Add a way to reconnect (if computer goes to sleep)
func main() {
	// getting options
	opt := GetDefaultOption()
	flags.Parse(&opt)

	// handle error
	if len(opt.Connect) == 0 && opt.Port == -1 {
		handleError(errors.New("Invalid arguments, please enter server ip or port"))
		fmt.Println(helpMsg)
		return
	}

	if opt.Help {
		fmt.Println(helpMsg)
		return
	}
	printDebugInfo = opt.Debug
	// --secure encrypts your data
	if opt.Secure {
		secure = true
		fmt.Print("Password for --secure: ")
		password, _ = terminal.ReadPassword(int(syscall.Stdin))
		fmt.Println()
	}
	if opt.Version {
		fmt.Println(version)
		return
	}
	if len(opt.Connect) != 0 { // has exactly one argument
		ConnectToServer(opt.Connect)
		return
	} else {
		makeServer(opt.Port)
	}
}

func makeServer(port int) {
	fmt.Println("Starting a new clipboard")
	ip := ":" + strconv.Itoa(port)
	l, err := net.Listen("tcp", ip) //nolint // complains about binding to all interfaces
	if err != nil {
		handleError(err)
		return
	}
	defer l.Close()
	p_str := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	fmt.Println("Run", "`uniclip", getOutboundIP().String()+":"+p_str+"`", "to join this clipboard")
	fmt.Println()
	for {
		c, err := l.Accept()
		if err != nil {
			handleError(err)
			return
		}
		fmt.Println("Connected to device at " + c.RemoteAddr().String())
		go HandleClient(c)
	}
}

// Handle a client as a server
func HandleClient(c net.Conn) {
	w := bufio.NewWriter(c)
	listOfClients = append(listOfClients, w)
	defer c.Close()
	go MonitorSentClips(bufio.NewReader(c))
	MonitorLocalClip(w)
}

// Connect to the server (which starts a new clipboard)
func ConnectToServer(address string) {
	c, err := net.Dial("tcp", address)
	fmt.Println("Connecting to server: " + address)
	if c == nil {
		handleError(err)
		fmt.Println("Could not connect to", address)
		return
	}
	if err != nil {
		handleError(err)
		return
	}
	defer func() { _ = c.Close() }()
	fmt.Println("Connected to the clipboard")
	go MonitorLocalClip(bufio.NewWriter(c))
	go MonitorSentClips(bufio.NewReader(c))
}

// monitors for changes to the local clipboard and writes them to w
func MonitorLocalClip(w *bufio.Writer) {
	for {
		localClipboard = getLocalClip()
		//debug("clipboard changed so sending it. localClipboard =", localClipboard
		err := sendClipboard(w, localClipboard)
		if err != nil {
			fmt.Println("Error Occured")
			handleError(err)
			return
		}
		for localClipboard == getLocalClip() {
			time.Sleep(time.Second * time.Duration(secondsBetweenChecksForClipChange))
		}
	}
}

// monitors for clipboards sent through r
func MonitorSentClips(r *bufio.Reader) {
	var foreignClipboard string
	var foreignClipboardBytes []byte
	for {
		err := gob.NewDecoder(r).Decode(&foreignClipboardBytes)
		if err != nil {
			if err == io.EOF {
				return // no need to monitor: disconnected
			}
			handleError(err)
			continue // continue getting next message
		}
		// OS Encoding to UTF-8
		result := common.GetBestCharset(foreignClipboardBytes)
		fmt.Println("Client String: %q, Detected Encoding:", foreignClipboardBytes, result.Charset)
		decoder := common.CvtEncoding(result.Charset).NewDecoder()
		utf8Bytes, _, _ := transform.Bytes(decoder, foreignClipboardBytes)

		// decrypt if needed
		if secure {
			foreignClipboardBytes, err = decrypt(password, foreignClipboardBytes)
			if err != nil {
				handleError(err)
				continue
			}
		}

		foreignClipboard = string(utf8Bytes)
		fmt.Println("UTF8string: %s", foreignClipboard)
		// hacky way to prevent empty clipboard TODO: find out why empty cb happens
		if foreignClipboard == "" {
			continue
		}
		//foreignClipboard = decompress(foreignClipboardBytes)
		setLocalClip(foreignClipboard)
		localClipboard = foreignClipboard
		debug("rcvd:", foreignClipboard)
		for i := range listOfClients {
			if listOfClients[i] != nil {
				err = sendClipboard(listOfClients[i], foreignClipboard)
				if err != nil {
					listOfClients[i] = nil
					fmt.Println("Error when trying to send the clipboard to a device. Will not contact that device again.")
				}
			}
		}
	}
}

// sendClipboard compresses and then if secure is enabled, encrypts data
func sendClipboard(w *bufio.Writer, clipboard string) error {
	var clipboardBytes []byte
	var err error
	clipboardBytes = []byte(clipboard)
	//clipboardBytes = compress(clipboard)
	//fmt.Printf("cmpr: %x\ndcmp: %x\nstr: %s\n\ncmpr better by %d\n", clipboardBytes, []byte(clipboard), clipboard, len(clipboardBytes)-len(clipboard))
	if secure {
		clipboardBytes, err = encrypt(password, clipboardBytes)
		if err != nil {
			return err
		}
	}

	err = gob.NewEncoder(w).Encode(clipboardBytes)
	if err != nil {
		return err
	}
	debug("sent:", clipboard)
	//if secure {
	//	debug("--secure is enabled, so actually sent as:", hex.EncodeToString(clipboardBytes))
	//}
	return w.Flush()
}

// Thanks to https://bruinsslot.jp/post/golang-crypto/ for crypto logic
func encrypt(key, data []byte) ([]byte, error) {
	key, salt, err := deriveKey(key, nil)
	if err != nil {
		return nil, err
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	ciphertext = append(ciphertext, salt...)
	return ciphertext, nil
}

func decrypt(key, data []byte) ([]byte, error) {
	salt, data := data[len(data)-32:], data[:len(data)-32]
	key, _, err := deriveKey(key, salt)
	if err != nil {
		return nil, err
	}
	blockCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func deriveKey(password, salt []byte) ([]byte, []byte, error) {
	if salt == nil {
		salt = make([]byte, 32)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, err
		}
	}
	key, err := scrypt.Key(password, salt, cryptoStrength, 8, 1, 32)
	if err != nil {
		return nil, nil, err
	}
	return key, salt, nil
}

func compress(str string) []byte {
	var buf bytes.Buffer
	zw, _ := flate.NewWriter(&buf, -1)
	_, _ = zw.Write([]byte(str))
	_ = zw.Close()
	return buf.Bytes()
}

func decompress(b []byte) string {
	var buf bytes.Buffer
	_, _ = buf.Write(b)
	zr := flate.NewReader(&buf)
	decompressed, err := ioutil.ReadAll(zr)
	if err != nil {
		handleError(err)
		return "Issues while decompressing clipboard"
	}
	_ = zr.Close()
	return string(decompressed)
}

func runGetClipCommand() string {
	var out []byte
	var err error
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbpaste")
	case "windows": //nolint // complains about literal string "windows" being used multiple times
		cmd = exec.Command("powershell.exe", "-command", "Get-Clipboard")
	default:
		if _, err = exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-out", "-selection", "clipboard")
		} else if _, err = exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "--output", "--clipboard")
		} else if _, err = exec.LookPath("wl-paste"); err == nil {
			cmd = exec.Command("wl-paste", "--no-newline")
		} else if _, err = exec.LookPath("termux-clipboard-get"); err == nil {
			cmd = exec.Command("termux-clipboard-get")
		} else {
			handleError(errors.New("sorry, uniclip won't work if you don't have xsel, xclip, wayland or Termux installed :(\nyou can create an issue at https://github.com/quackduck/uniclip/issues"))
			os.Exit(2)
		}
	}
	if out, err = cmd.Output(); err != nil {
		handleError(err)
		return "An error occurred wile getting the local clipboard"
	}

	// OS Encoding to UTF-8
	result := common.GetBestCharset(out)
	fmt.Println("Original String: %q, Detected Encoding:", out, result.Charset)
	decoder := common.CvtEncoding(result.Charset).NewDecoder()
	utf8Bytes, _, _ := transform.Bytes(decoder, out)
	utf8String := string(utf8Bytes)
	fmt.Println("UTF8string: %s", utf8String)
	if runtime.GOOS == "windows" {
		return strings.TrimSuffix(utf8String, "\r\n") // powershell's get-clipboard adds a windows newline to the end for some reason
	}
	return string(utf8String)
}

func getLocalClip() string {
	// return UTF-8 Encoded String
	str := runGetClipCommand()
	//for ; str == ""; str = runGetClipCommand() { // wait until it's not empty
	//	time.Sleep(time.Millisecond * 100)
	//}
	return str
}

func setLocalClip(s string) {
	var copyCmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		copyCmd = exec.Command("pbcopy")
	case "windows":
		copyCmd = exec.Command("clip")
	default:
		if _, err := exec.LookPath("xclip"); err == nil {
			copyCmd = exec.Command("xclip", "-in", "-selection", "clipboard")
		} else if _, err = exec.LookPath("xsel"); err == nil {
			copyCmd = exec.Command("xsel", "--input", "--clipboard")
		} else if _, err = exec.LookPath("wl-copy"); err == nil {
			copyCmd = exec.Command("wl-copy")
		} else if _, err = exec.LookPath("termux-clipboard-set"); err == nil {
			copyCmd = exec.Command("termux-clipboard-set")
		} else {
			handleError(errors.New("sorry, uniclip won't work if you don't have xsel, xclip, wayland or Termux:API installed :(\nyou can create an issue at https://github.com/quackduck/uniclip/issues"))
			os.Exit(2)
		}
	}
	in, err := copyCmd.StdinPipe()
	if err != nil {
		handleError(err)
		return
	}
	if err = copyCmd.Start(); err != nil {
		handleError(err)
		return
	}
	if _, err = in.Write([]byte(s)); err != nil {
		handleError(err)
		return
	}
	if err = in.Close(); err != nil {
		handleError(err)
		return
	}
	if err = copyCmd.Wait(); err != nil {
		handleError(err)
		return
	}
}

func getOutboundIP() net.IP {
	// https://stackoverflow.com/questions/23558425/how-do-i-get-the-local-ip-address-in-go/37382208#37382208
	conn, err := net.Dial("udp", "8.8.8.8:80") // address can be anything. Doesn't even have to exist
	if err != nil {
		handleError(err)
		return nil
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP
}

func handleError(err error) {
	if err == io.EOF {
		fmt.Println("Disconnected")
	} else {
		fmt.Fprintln(os.Stderr, "error: ["+err.Error()+"]")
	}
}

func debug(a ...interface{}) {
	if printDebugInfo {
		fmt.Println("verbose:", a)
	}
}
