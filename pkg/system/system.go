package system

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/angelfreak/net/pkg/types"
	"github.com/sirupsen/logrus"
)

// Default timeout for commands that don't specify one
const DefaultCommandTimeout = 30 * time.Second

// Executor implements the SystemExecutor interface
type Executor struct {
	logger types.Logger
	debug  bool
}

// NewExecutor creates a new system executor
func NewExecutor(logger types.Logger, debug bool) *Executor {
	return &Executor{
		logger: logger,
		debug:  debug,
	}
}

// Execute runs a command and returns its output (uses default timeout)
func (e *Executor) Execute(cmd string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultCommandTimeout)
	defer cancel()
	return e.ExecuteContext(ctx, cmd, args...)
}

// ExecuteContext runs a command with context support for cancellation and timeouts
func (e *Executor) ExecuteContext(ctx context.Context, cmd string, args ...string) (string, error) {
	fullCmd := cmd
	if len(args) > 0 {
		fullCmd += " " + strings.Join(args, " ")
	}

	if e.debug {
		e.logger.Info("Executing command", "cmd", fullCmd)
	}

	command := exec.CommandContext(ctx, cmd, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr

	err := command.Run()
	output := strings.TrimSpace(stdout.String())
	errorOutput := strings.TrimSpace(stderr.String())

	if e.debug {
		if output != "" {
			e.logger.Debug("Command output", "output", output)
		}
		if errorOutput != "" {
			e.logger.Debug("Command stderr", "stderr", errorOutput)
		}
	}

	if err != nil {
		// Check if context was cancelled or timed out
		if ctx.Err() == context.DeadlineExceeded {
			return output, fmt.Errorf("command timed out: %s", fullCmd)
		}
		if ctx.Err() == context.Canceled {
			return output, fmt.Errorf("command cancelled: %s", fullCmd)
		}
		return output, fmt.Errorf("command failed: %w (stderr: %s)", err, errorOutput)
	}

	return output, nil
}

// ExecuteWithTimeout runs a command with a specific timeout
func (e *Executor) ExecuteWithTimeout(timeout time.Duration, cmd string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return e.ExecuteContext(ctx, cmd, args...)
}

// ExecuteWithInput runs a command with stdin input and returns its output
func (e *Executor) ExecuteWithInput(cmd string, input string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultCommandTimeout)
	defer cancel()
	return e.ExecuteWithInputContext(ctx, cmd, input, args...)
}

// ExecuteWithInputContext runs a command with stdin input and context support
func (e *Executor) ExecuteWithInputContext(ctx context.Context, cmd string, input string, args ...string) (string, error) {
	fullCmd := cmd
	if len(args) > 0 {
		fullCmd += " " + strings.Join(args, " ")
	}

	if e.debug {
		e.logger.Info("Executing command with input", "cmd", fullCmd)
	}

	command := exec.CommandContext(ctx, cmd, args...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	command.Stdin = strings.NewReader(input)

	err := command.Run()
	output := strings.TrimSpace(stdout.String())
	errorOutput := strings.TrimSpace(stderr.String())

	if e.debug {
		if output != "" {
			e.logger.Debug("Command output", "output", output)
		}
		if errorOutput != "" {
			e.logger.Debug("Command stderr", "stderr", errorOutput)
		}
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return output, fmt.Errorf("command timed out: %s", fullCmd)
		}
		if ctx.Err() == context.Canceled {
			return output, fmt.Errorf("command cancelled: %s", fullCmd)
		}
		return output, fmt.Errorf("command failed: %w (stderr: %s)", err, errorOutput)
	}

	return output, nil
}

// Logger implements the Logger interface using logrus
type LogrusLogger struct {
	logger *logrus.Logger
}

// NewLogger creates a new logger
func NewLogger(debug bool) *LogrusLogger {
	logger := logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	if debug {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		// Only show warnings and errors by default
		logger.SetLevel(logrus.WarnLevel)
	}

	return &LogrusLogger{
		logger: logger,
	}
}

// Debug logs a debug message
func (l *LogrusLogger) Debug(msg string, fields ...interface{}) {
	if len(fields) > 0 {
		l.logger.WithFields(l.toFields(fields...)).Debug(msg)
	} else {
		l.logger.Debug(msg)
	}
}

// Info logs an info message
func (l *LogrusLogger) Info(msg string, fields ...interface{}) {
	if len(fields) > 0 {
		l.logger.WithFields(l.toFields(fields...)).Info(msg)
	} else {
		l.logger.Info(msg)
	}
}

// Warn logs a warning message
func (l *LogrusLogger) Warn(msg string, fields ...interface{}) {
	if len(fields) > 0 {
		l.logger.WithFields(l.toFields(fields...)).Warn(msg)
	} else {
		l.logger.Warn(msg)
	}
}

// Error logs an error message
func (l *LogrusLogger) Error(msg string, fields ...interface{}) {
	if len(fields) > 0 {
		l.logger.WithFields(l.toFields(fields...)).Error(msg)
	} else {
		l.logger.Error(msg)
	}
}

// toFields converts interface{} pairs to logrus.Fields
func (l *LogrusLogger) toFields(fields ...interface{}) logrus.Fields {
	result := make(logrus.Fields)
	for i := 0; i < len(fields); i += 2 {
		if i+1 < len(fields) {
			key := fmt.Sprintf("%v", fields[i])
			result[key] = fields[i+1]
		}
	}
	return result
}

// HasCommand checks if a command exists in PATH
func (e *Executor) HasCommand(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}
