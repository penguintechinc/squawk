package logger

import (
	"fmt"
	"log"
	"os"
)

// Logger interface for performance monitoring
type Logger interface {
	Info(format string, args ...interface{})
	Debug(format string, args ...interface{})
	Error(format string, args ...interface{})
	Printf(format string, args ...interface{})
}

// SimpleLogger implements basic logging functionality
type SimpleLogger struct {
	verbose bool
	logger  *log.Logger
}

// NewSimpleLogger creates a new simple logger
func NewSimpleLogger(verbose bool) Logger {
	return &SimpleLogger{
		verbose: verbose,
		logger:  log.New(os.Stdout, "[Squawk] ", log.LstdFlags),
	}
}

// Info logs an info message
func (l *SimpleLogger) Info(format string, args ...interface{}) {
	l.logger.Printf("INFO: "+format, args...)
}

// Debug logs a debug message (only if verbose is enabled)
func (l *SimpleLogger) Debug(format string, args ...interface{}) {
	if l.verbose {
		l.logger.Printf("DEBUG: "+format, args...)
	}
}

// Error logs an error message
func (l *SimpleLogger) Error(format string, args ...interface{}) {
	l.logger.Printf("ERROR: "+format, args...)
}

// Printf logs a formatted message
func (l *SimpleLogger) Printf(format string, args ...interface{}) {
	fmt.Printf(format, args...)
}