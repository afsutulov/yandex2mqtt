package bridge

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

type LoggingConfig struct {
	Level string `json:"level,omitempty"`
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
