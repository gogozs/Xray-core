package main

import (
	"encoding/json"
	"fmt"
	"github.com/xtls/xray-core/infra/conf"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
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

func init() {
	cmdStart.Run = executeStart // break init loop
}

var (
	data string

	/* We have to do this here because Golang's Test will also need to parse flag, before
	 * main func in this file is run.
	 */
	_ = func() bool {
		cmdStart.Flag.StringVar(&data, "data", "", "The xray json config")

		return true
	}()
)

func executeStart(cmd *base.Command, args []string) {
	printVersion()
	var jsonConfig conf.Config
	if err := json.Unmarshal([]byte(data), &jsonConfig); err != nil {
		fmt.Println("Failed to unmarshal config:", err)
		// Configuration error. Exit with a special value to prevent systemd from restarting.
		os.Exit(23)
	}
	config, err := jsonConfig.Build()
	if err != nil {
		fmt.Println("Failed to build config:", err)
		// Configuration error. Exit with a special value to prevent systemd from restarting.
		os.Exit(23)
	}
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

func startXrayWithConfig(c *core.Config) (core.Server, error) {
	server, err := core.New(c)
	if err != nil {
		return nil, newError("failed to create server").Base(err)
	}

	return server, nil
}
