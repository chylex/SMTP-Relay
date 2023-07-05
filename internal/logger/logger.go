package logger

import (
	"fmt"
	"os"
	"time"

	"github.com/sirupsen/logrus"
)

func SetupLogger(file *string, levelName string, formatName string) *logrus.Logger {
	log := logrus.New()

	if *file == "" {
		log.SetOutput(os.Stderr)
	} else {
		writer, err := os.OpenFile(*file, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot open log file: %s\n", err)
			os.Exit(1)
		}

		log.SetOutput(writer)
	}

	formatter, err := createFormatter(formatName)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	} else {
		log.SetFormatter(formatter)
	}

	level, err := logrus.ParseLevel(levelName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid log level: %s\n", levelName)
		os.Exit(1)
	} else {
		log.SetLevel(level)
	}

	return log
}

func createFormatter(format string) (logrus.Formatter, error) {
	switch format {
	case "json":
		return &logrus.JSONFormatter{
			TimestampFormat:   time.RFC3339Nano,
			DisableHTMLEscape: true,
		}, nil

	case "plain":
		return &logrus.TextFormatter{
			DisableTimestamp: true,
		}, nil

	case "", "default":
		return &logrus.TextFormatter{
			FullTimestamp: true,
		}, nil

	default:
		return nil, fmt.Errorf("Invalid log_format: %s\n", format)
	}
}
