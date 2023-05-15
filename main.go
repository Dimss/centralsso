package main

import (
	"fmt"
	"github.com/AccessibleAI/centralsso/pkg/srv"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

type param struct {
	name      string
	shorthand string
	value     interface{}
	usage     string
	required  bool
}

var (
	Version string
	Build   string

	rootParams = []param{
		{name: "bind-addr", shorthand: "", value: "0.0.0.0:8080", usage: "listen address"},
		{name: "bg-color", shorthand: "", value: "white", usage: "page background"},
		{name: "title", shorthand: "", value: "Cnvrg SSO Central", usage: "page title"},
		{name: "sign-key", shorthand: "", value: "./config/private-key", usage: "path to private key for jwt sign"},
		{name: "domain-id", shorthand: "", value: "localhost", usage: "the domain id which will be used as a group"},
		{name: "jwt-iis", shorthand: "", value: "iis", usage: "the jwt iis"},
		{name: "app-url", shorthand: "", value: "app-url", usage: "App url for default redirect"},
	}
	rootCmd = &cobra.Command{
		Use:   "centralsso",
		Short: "centralsso - cnvrg central sso test app ",
		Run: func(cmd *cobra.Command, args []string) {
			srv.Run(viper.GetString("bind-addr"), viper.GetString("bg-color"), viper.GetString("title"))
			// handle interrupts
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
			for {
				select {
				case s := <-sigCh:
					log.Infof("signal: %s, shutting down", s)
					log.Info("bye bye 👋")
					os.Exit(0)
				}
			}
		},
	}
)

func init() {
	cobra.OnInitialize(initConfig)
	setParams(rootParams, rootCmd)
}

func setParams(params []param, command *cobra.Command) {
	for _, param := range params {
		switch v := param.value.(type) {
		case int:
			command.PersistentFlags().IntP(param.name, param.shorthand, v, param.usage)
		case string:
			command.PersistentFlags().StringP(param.name, param.shorthand, v, param.usage)
		case bool:
			command.PersistentFlags().BoolP(param.name, param.shorthand, v, param.usage)
		}
		if err := viper.BindPFlag(param.name, command.PersistentFlags().Lookup(param.name)); err != nil {
			panic(err)
		}
	}
}

func initConfig() {
	setupLogging()
	viper.AutomaticEnv()
	viper.SetEnvPrefix("CNVRG_CENTRAL_SSO")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
}

func setupLogging() {

	log.SetReportCaller(true)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp: true,
		DisableColors: true,
		CallerPrettyfier: func(frame *runtime.Frame) (function string, file string) {
			fileName := strings.TrimSuffix(filepath.Base(frame.File), filepath.Ext(frame.File))
			line := strconv.Itoa(frame.Line)
			return "", fmt.Sprintf("%s:%s", fileName, line)
		},
	})
}

func main() {

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

}
