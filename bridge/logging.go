package bridge

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

type LoggingConfig struct {
	Level     string `json:"level,omitempty"`
	File      string `json:"file,omitempty"`
	ToConsole *bool  `json:"to_console,omitempty"`
}

func (c LoggingConfig) ConsoleEnabled() bool { return c.ToConsole == nil || *c.ToConsole }

func (c LoggingConfig) Validate() error {
	if _, err := c.ParseLevel(); err != nil {
		return err
	}
	if strings.ContainsRune(c.File, '\x00') {
		return fmt.Errorf("logging.file must not contain NUL")
	}
	return nil
}

// OpenOutput opens the configured destinations. Close releases only the owned
// log file; the caller's console writer is never closed.
func (c LoggingConfig) OpenOutput(console io.Writer) (io.WriteCloser, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.ConsoleEnabled() && console == nil {
		return nil, fmt.Errorf("console logging enabled but no console writer provided")
	}
	var writers []io.Writer
	output := &loggingOutput{}
	if c.File != "" {
		if err := os.MkdirAll(filepath.Dir(c.File), 0750); err != nil {
			return nil, fmt.Errorf("create log directory for %q: %w", c.File, err)
		}
		file, err := os.OpenFile(c.File, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			return nil, fmt.Errorf("open log file %q: %w", c.File, err)
		}
		output.file = file
		writers = append(writers, file)
	}
	if c.ConsoleEnabled() {
		writers = append(writers, console)
	}
	output.Writer = io.Discard
	if len(writers) != 0 {
		output.Writer = io.MultiWriter(writers...)
	}
	return output, nil
}

type loggingOutput struct {
	io.Writer
	file *os.File
}

func (o *loggingOutput) Close() error {
	if o.file != nil {
		return o.file.Close()
	}
	return nil
}

func (c LoggingConfig) ParseLevel() (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(c.Level)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("logging.level must be debug, info, warn or error")
	}
}

func NewLogger(output io.Writer, c LoggingConfig) (*slog.Logger, error) {
	level, err := c.ParseLevel()
	if err != nil {
		return nil, err
	}
	return slog.New(slog.NewJSONHandler(output, &slog.HandlerOptions{Level: level})), nil
}
