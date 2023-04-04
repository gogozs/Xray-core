package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/infra/conf"
	"io"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/main/commands/base"
)

var cmdStart = &base.Command{
	UsageLine: "{{.Exec}} start [-data <content>]",
	Short:     "Run Xray with config, the default command",
	Long: `
Run Xray with config, the default command.
 `,
}

var secretKey = ""

func init() {
	cmdStart.Run = executeStart // break init loop
}

var (
	data      string
	httpAddr  string
	socksAddr string

	/* We have to do this here because Golang's Test will also need to parse flag, before
	 * main func in this file is run.
	 */
	_ = func() bool {
		cmdStart.Flag.StringVar(&data, "data", "", "The xray json config")
		cmdStart.Flag.StringVar(&httpAddr, "httpAddr", "", "Config the xray http address")
		cmdStart.Flag.StringVar(&socksAddr, "socksAddr", "", "Config the xray socks address")

		return true
	}()
)

func parseConfig() *core.Config {
	decryptedData := decode()

	var jsonConfig conf.Config
	if err := json.Unmarshal(decryptedData, &jsonConfig); err != nil {
		fmt.Println("Failed to unmarshal config:", err)
		// Configuration error. Exit with a special value to prevent systemd from restarting.
		os.Exit(23)
	}
	if httpAddr != "" {
		listenOn, portList, err := parseAddress(httpAddr)
		if err != nil {
			fmt.Println("Failed to unmarshal httAddr:", err)
			os.Exit(23)
		}
		jsonConfig.InboundConfigs[0].ListenOn = listenOn
		jsonConfig.InboundConfigs[0].PortList = portList
	}
	if socksAddr != "" {
		listenOn, portList, err := parseAddress(socksAddr)
		if err != nil {
			fmt.Println("Failed to unmarshal socksAddr:", err)
			os.Exit(23)
		}
		jsonConfig.InboundConfigs[1].ListenOn = listenOn
		jsonConfig.InboundConfigs[1].PortList = portList
	}

	config, err := jsonConfig.Build()
	if err != nil {
		fmt.Println("Failed to build config:", err)
		// Configuration error. Exit with a special value to prevent systemd from restarting.
		os.Exit(23)
	}
	return config
}

func parseAddress(addr string) (*conf.Address, *conf.PortList, error) {
	arr := strings.Split(addr, ":")
	if len(arr) < 2 {
		return nil, nil, errors.New(fmt.Sprintf("invalid address: %s", addr))
	}
	ip := net.ParseAddress(arr[0])
	var port conf.PortList
	if err := json.Unmarshal([]byte(arr[1]), &port); err != nil {
		return nil, nil, errors.New(fmt.Sprintf("invalid port: %s", addr))
	}

	return &conf.Address{Address: ip}, &port, nil
}

func executeStart(cmd *base.Command, args []string) {
	printVersion()
	config := parseConfig()

	server, err := startXrayWithConfig(config)
	if err != nil {
		fmt.Println("Failed to start:", err)
		// Configuration error. Exit with a special value to prevent systemd from restarting.
		os.Exit(23)
	}

	if *test {
		fmt.Println("Configuration OK.")
		os.Exit(0)
	}

	if err := server.Start(); err != nil {
		fmt.Println("Failed to start:", err)
		os.Exit(-1)
	}
	defer server.Close()

	// Explicitly triggering GC to remove garbage from config loading.
	runtime.GC()
	debug.FreeOSMemory()

	{
		osSignals := make(chan os.Signal, 1)
		signal.Notify(osSignals, os.Interrupt, syscall.SIGTERM)
		<-osSignals
	}
}

func decode() []byte {
	decodeData, err := Base64Decode(data)
	if err != nil {
		fmt.Println("Failed to decode base64:", err)
		// Configuration error. Exit with a special value to prevent systemd from restarting.
		os.Exit(23)
	}
	decryptedData, err := AesDecryptCBC(decodeData, []byte(secretKey))
	if err != nil {
		fmt.Println("Failed to decode aes:", err)
		// Configuration error. Exit with a special value to prevent systemd from restarting.
		os.Exit(23)
	}
	return decryptedData
}

func startXrayWithConfig(c *core.Config) (core.Server, error) {
	server, err := core.New(c)
	if err != nil {
		return nil, newError("failed to create server").Base(err)
	}

	return server, nil
}

func AesEncryptCBC(origData []byte, key []byte) (encrypted []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origData = pkcs5Padding(origData, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	encrypted = make([]byte, len(origData))
	blockMode.CryptBlocks(encrypted, origData)
	return encrypted, nil
}

func AesDecryptCBC(encrypted []byte, key []byte) (decrypted []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	decrypted = make([]byte, len(encrypted))
	blockMode.CryptBlocks(decrypted, encrypted)
	decrypted = pkcs5UnPadding(decrypted)
	return decrypted, nil
}

func pkcs5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func pkcs5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func AesEncryptECB(origData []byte, key []byte) (encrypted []byte, err error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	length := (len(origData) + aes.BlockSize) / aes.BlockSize
	plain := make([]byte, length*aes.BlockSize)
	copy(plain, origData)
	pad := byte(len(plain) - len(origData))
	for i := len(origData); i < len(plain); i++ {
		plain[i] = pad
	}
	encrypted = make([]byte, len(plain))
	for bs, be := 0, cipher.BlockSize(); bs <= len(origData); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Encrypt(encrypted[bs:be], plain[bs:be])
	}

	return encrypted, nil
}

func AesDecryptECB(encrypted []byte, key []byte) (decrypted []byte, err error) {
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	decrypted = make([]byte, len(encrypted))
	for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}

	trim := 0
	if len(decrypted) > 0 {
		trim = len(decrypted) - int(decrypted[len(decrypted)-1])
	}

	return decrypted[:trim], nil
}

func generateKey(key []byte) (genKey []byte) {
	genKey = make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}
	return genKey
}

func AesEncryptCFB(origData []byte, key []byte) (encrypted []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	encrypted = make([]byte, aes.BlockSize+len(origData))
	iv := encrypted[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(encrypted[aes.BlockSize:], origData)
	return encrypted, nil
}

func AesDecryptCFB(encrypted []byte, key []byte) (decrypted []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(encrypted) < aes.BlockSize {
		panic("ciphertext too short")
	}
	iv := encrypted[:aes.BlockSize]
	encrypted = encrypted[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(encrypted, encrypted)
	return encrypted, nil
}

func Base64Encode(src []byte) string {
	return base64.StdEncoding.EncodeToString(src)
}

func Base64Decode(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
