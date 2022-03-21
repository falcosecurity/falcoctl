package cmd

import (
	"context"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	homedir "github.com/mitchellh/go-homedir"
	logger "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

const (
	configName = "config"
	configDir  = ".falcoctl"
)

func init() {
	logger.SetFormatter(&logger.TextFormatter{
		ForceColors:            true,
		DisableLevelTruncation: false,
		DisableTimestamp:       true,
	})
}

// New instantiates the root command.
func New(configOptions *ConfigOptions) *cobra.Command {
	if configOptions == nil {
		configOptions = NewConfigOptions()
	}
	rootCmd := &cobra.Command{
		Use:               "falcoctl",
		Short:             "The control tool for running Falco in Kubernetes",
		DisableAutoGenTag: true,
		PersistentPreRun: func(c *cobra.Command, args []string) {
			// PersistentPreRun runs before flags validation but after args validation.
			// Do not assume initialization completed during args validation.

			// at this stage configOptions is bound to command line flags only
			validateConfig(*configOptions)
			initLogger(configOptions.LogLevel)
			logger.Debugf("running with args: %s", strings.Join(os.Args, " "))
			initConfig(configOptions.ConfigFile)

			// then bind all flags to ENV and config file
			flags := c.Flags()
			initEnv()
			initFlags(flags, map[string]bool{
				// exclude flags to be not bound to ENV and config file
				"config":      true,
				"loglevel":    true,
				"help":        true,
				"registryurl": false,
			})
			//validateConfig(*configOptions) // enable if other flags were bound to configOptions
			debugFlags(flags)
		},
		Run: func(c *cobra.Command, args []string) {
			c.Help()
		},
	}

	// Global flags
	flags := rootCmd.PersistentFlags()
	flags.StringVarP(&configOptions.ConfigFile, "config", "c", configOptions.ConfigFile, "Config file path (default "+filepath.Join("$HOME", configDir, configName+"yaml")+" if exists)")
	flags.StringVarP(&configOptions.LogLevel, "loglevel", "l", configOptions.LogLevel, "Log level")

	// Commands
	rootCmd.AddCommand(NewDeleteCmd(nil))
	rootCmd.AddCommand(NewInstallCmd(NewInstallOptions()))
	rootCmd.AddCommand(NewSearchCmd(NewSearchOptions()))

	return rootCmd
}

// Execute creates the root command and runs it.
func Execute() {
	ctx := WithSignals(context.Background())
	if err := New(nil).ExecuteContext(ctx); err != nil {
		logger.WithError(err).Fatal("error executing falcoctl")
	}
}

// WithSignals returns a copy of ctx with a new Done channel.
// The returned context's Done channel is closed when a SIGKILL or SIGTERM signal is received.
func WithSignals(ctx context.Context) context.Context {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)

	ctx, cancel := context.WithCancel(ctx)
	go func() {
		defer cancel()
		select {
		case <-ctx.Done():
			return
		case s := <-sigCh:
			switch s {
			case os.Interrupt:
				logger.Infof("received SIGINT")
			case syscall.SIGTERM:
				logger.Infof("received SIGTERM")
			}
			return
		}
	}()
	return ctx
}

// validateConfig
func validateConfig(configOptions ConfigOptions) {
	if errs := configOptions.Validate(); errs != nil {
		for _, err := range errs {
			logger.WithError(err).Error("error validating config options")
		}
		logger.Fatal("exiting for validation errors")
	}
}

// initEnv enables automatic ENV variables lookup
func initEnv() {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("falcoctl")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))
}

// initLogger configures the logger
func initLogger(logLevel string) {
	lvl, err := logger.ParseLevel(logLevel)
	if err != nil {
		logger.Fatal(err)
	}
	logger.SetLevel(lvl)
}

// initConfig reads in config file, if any. Default location is ~/.falcoctl/config.yaml
func initConfig(configFile string) {
	if configFile != "" {
		viper.SetConfigFile(configFile)
	} else {
		// Find home directory.
		home, err := homedir.Dir()
		if err != nil {
			logger.WithError(err).Fatal("error getting the home directory")
		}

		viper.AddConfigPath(filepath.Join(home, configDir))
		viper.SetConfigName(configName)
		viper.SetConfigType("yaml")
	}

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		logger.WithField("file", viper.ConfigFileUsed()).Info("using config file")
	} else {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			// Config file not found, ignore ...
			logger.Debugf("running without a configuration file")
		} else {
			// Config file was found but another error was produced
			logger.WithField("file", viper.ConfigFileUsed()).WithError(err).Fatal("error running with config file")
		}
	}
}

// initFlags binds a full flag set to the configuration, using each flag's long name as the config key.
//
// Assuming viper's `AutomaticEnv` is enabled, when a flag is not present in the command line
// will fallback to one of (in order of precedence):
// - ENV (with FALCOCTL prefix)
// - config file (e.g. ~/.falcoctl.yaml)
// - its default
func initFlags(flags *pflag.FlagSet, exclude map[string]bool) {
	viper.BindPFlags(flags)
	flags.VisitAll(func(f *pflag.Flag) {
		if exclude[f.Name] {
			return
		}
		viper.SetDefault(f.Name, f.DefValue)
		if v := viper.GetString(f.Name); v != f.DefValue {
			flags.Set(f.Name, v)
		}
	})
}

func debugFlags(flags *pflag.FlagSet) {
	fields := logger.Fields{}
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			fields[f.Name] = f.Value
		}
	})
	logger.WithFields(fields).Debug("running with options")
}
