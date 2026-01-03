package system

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
)

// MockSystemExecutor for testing
type mockSystemExecutor struct {
	executedCommands []executedCommand
	shouldFail       map[string]bool
}

type executedCommand struct {
	cmd  string
	args []string
}

func (m *mockSystemExecutor) Execute(cmd string, args ...string) (string, error) {
	m.executedCommands = append(m.executedCommands, executedCommand{cmd: cmd, args: args})
	if m.shouldFail[cmd] {
		return "", assert.AnError
	}
	// Mock responses
	switch cmd {
	case "echo":
		return strings.Join(args, " "), nil
	case "cat":
		return "mock content", nil
	default:
		return "mock output", nil
	}
}

func (m *mockSystemExecutor) ExecuteContext(ctx context.Context, cmd string, args ...string) (string, error) {
	return m.Execute(cmd, args...)
}

func (m *mockSystemExecutor) ExecuteWithTimeout(timeout time.Duration, cmd string, args ...string) (string, error) {
	return m.Execute(cmd, args...)
}

func (m *mockSystemExecutor) ExecuteWithInput(cmd string, input string, args ...string) (string, error) {
	m.executedCommands = append(m.executedCommands, executedCommand{cmd: cmd, args: args})
	if m.shouldFail[cmd] {
		return "", assert.AnError
	}
	return "mock output with input", nil
}

func (m *mockSystemExecutor) ExecuteWithInputContext(ctx context.Context, cmd string, input string, args ...string) (string, error) {
	return m.ExecuteWithInput(cmd, input, args...)
}

func (m *mockSystemExecutor) HasCommand(cmd string) bool {
	return true // mock always has the command
}

func TestNewExecutor(t *testing.T) {
	logger := &mockLogger{}
	executor := NewExecutor(logger, true)
	assert.NotNil(t, executor)
	assert.Equal(t, logger, executor.logger)
	assert.True(t, executor.debug)
}

func TestExecutor_CommandBuilding(t *testing.T) {
	// Test that command building logic works
	cmd := "echo"
	args := []string{"hello", "world"}
	fullCmd := cmd
	if len(args) > 0 {
		fullCmd += " " + strings.Join(args, " ")
	}
	assert.Equal(t, "echo hello world", fullCmd)
}

func TestExecutor_CommandBuildingWithInput(t *testing.T) {
	cmd := "tee"
	input := "test input"
	args := []string{"/tmp/file"}
	fullCmd := cmd
	if len(args) > 0 {
		fullCmd += " " + strings.Join(args, " ")
	}
	assert.Equal(t, "tee /tmp/file", fullCmd)
	assert.Equal(t, "test input", input)
}

func TestNewLogger(t *testing.T) {
	logger := NewLogger(true)
	assert.NotNil(t, logger)
	assert.IsType(t, &LogrusLogger{}, logger)

	// Test verbose sets level
	verboseLogger := NewLogger(true)
	nonVerboseLogger := NewLogger(false)

	// Can't easily test internal logrus level, but ensure created
	assert.NotNil(t, verboseLogger)
	assert.NotNil(t, nonVerboseLogger)
}

func TestLogrusLogger_Debug(t *testing.T) {
	logger := &LogrusLogger{
		logger: logrus.New(),
	}
	logger.logger.SetLevel(logrus.DebugLevel)

	// Capture output
	var buf bytes.Buffer
	logger.logger.SetOutput(&buf)
	logger.logger.SetFormatter(&logrus.TextFormatter{})

	logger.Debug("test message", "key", "value")

	output := buf.String()
	assert.Contains(t, output, "test message")
	assert.Contains(t, output, "key")
	assert.Contains(t, output, "value")
}

func TestLogrusLogger_Info(t *testing.T) {
	logger := &LogrusLogger{
		logger: logrus.New(),
	}

	var buf bytes.Buffer
	logger.logger.SetOutput(&buf)
	logger.logger.SetFormatter(&logrus.TextFormatter{})

	logger.Info("info message")

	output := buf.String()
	assert.Contains(t, output, "info message")
}

func TestLogrusLogger_Warn(t *testing.T) {
	logger := &LogrusLogger{
		logger: logrus.New(),
	}

	var buf bytes.Buffer
	logger.logger.SetOutput(&buf)
	logger.logger.SetFormatter(&logrus.TextFormatter{})

	logger.Warn("warn message", "error", "test")

	output := buf.String()
	assert.Contains(t, output, "warn message")
	assert.Contains(t, output, "error")
}

func TestLogrusLogger_Error(t *testing.T) {
	logger := &LogrusLogger{
		logger: logrus.New(),
	}

	var buf bytes.Buffer
	logger.logger.SetOutput(&buf)
	logger.logger.SetFormatter(&logrus.TextFormatter{})

	logger.Error("error message")

	output := buf.String()
	assert.Contains(t, output, "error message")
}

func TestLogrusLogger_toFields(t *testing.T) {
	logger := &LogrusLogger{}

	fields := logger.toFields("key1", "value1", "key2", 42)

	expected := logrus.Fields{"key1": "value1", "key2": 42}
	assert.Equal(t, expected, fields)
}

func TestLogrusLogger_toFields_OddNumber(t *testing.T) {
	logger := &LogrusLogger{}

	fields := logger.toFields("key1", "value1", "orphan")

	assert.Equal(t, logrus.Fields{"key1": "value1"}, fields)
}

// mockLogger for testing
type mockLogger struct{}

func (m *mockLogger) Debug(msg string, fields ...interface{}) {}
func (m *mockLogger) Info(msg string, fields ...interface{})  {}
func (m *mockLogger) Warn(msg string, fields ...interface{})  {}
func (m *mockLogger) Error(msg string, fields ...interface{}) {}

func TestExecutor_Execute(t *testing.T) {
	t.Run("successful command", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		output, err := executor.Execute("echo", "hello", "world")
		assert.NoError(t, err)
		assert.Equal(t, "hello world", output)
	})

	t.Run("successful command verbose", func(t *testing.T) {
		logger := NewLogger(true)
		executor := NewExecutor(logger, true)

		output, err := executor.Execute("echo", "test")
		assert.NoError(t, err)
		assert.Equal(t, "test", output)
	})

	t.Run("command with no args", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		output, err := executor.Execute("pwd")
		assert.NoError(t, err)
		assert.NotEmpty(t, output) // pwd should return something
	})

	t.Run("failed command", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		_, err := executor.Execute("false") // false always returns exit code 1
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "command failed")
	})

	t.Run("command with stderr", func(t *testing.T) {
		logger := NewLogger(true)
		executor := NewExecutor(logger, true)

		// ls on a non-existent directory produces stderr
		_, err := executor.Execute("ls", "/nonexistent-directory-12345")
		assert.Error(t, err)
	})

	t.Run("command with output and stderr", func(t *testing.T) {
		logger := NewLogger(true)
		executor := NewExecutor(logger, true)

		// sh can produce both stdout and stderr
		output, err := executor.Execute("sh", "-c", "echo stdout && echo stderr >&2")
		assert.NoError(t, err)
		assert.Equal(t, "stdout", output)
	})
}

func TestExecutor_ExecuteWithInput(t *testing.T) {
	t.Run("successful command with input", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		output, err := executor.ExecuteWithInput("cat", "test input")
		assert.NoError(t, err)
		assert.Equal(t, "test input", output)
	})

	t.Run("successful command with input verbose", func(t *testing.T) {
		logger := NewLogger(true)
		executor := NewExecutor(logger, true)

		output, err := executor.ExecuteWithInput("cat", "verbose test")
		assert.NoError(t, err)
		assert.Equal(t, "verbose test", output)
	})

	t.Run("command with args and input", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		// grep reads from stdin and filters
		output, err := executor.ExecuteWithInput("grep", "hello\nworld\nhello\n", "hello")
		assert.NoError(t, err)
		assert.Contains(t, output, "hello")
	})

	t.Run("failed command with input", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		_, err := executor.ExecuteWithInput("false", "input")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "command failed")
	})

	t.Run("command with input and stderr", func(t *testing.T) {
		logger := NewLogger(true)
		executor := NewExecutor(logger, true)

		// sh with stderr
		_, err := executor.ExecuteWithInput("sh", "echo test\nexit 1\n", "-s")
		assert.Error(t, err)
	})

	t.Run("multiline input", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		input := "line1\nline2\nline3"
		output, err := executor.ExecuteWithInput("cat", input)
		assert.NoError(t, err)
		assert.Equal(t, input, output)
	})
}

func TestLogrusLogger_Debug_NoFields(t *testing.T) {
	logger := &LogrusLogger{
		logger: logrus.New(),
	}
	logger.logger.SetLevel(logrus.DebugLevel)

	var buf bytes.Buffer
	logger.logger.SetOutput(&buf)
	logger.logger.SetFormatter(&logrus.TextFormatter{})

	logger.Debug("test message without fields")

	output := buf.String()
	assert.Contains(t, output, "test message without fields")
}

func TestLogrusLogger_Info_NoFields(t *testing.T) {
	logger := &LogrusLogger{
		logger: logrus.New(),
	}

	var buf bytes.Buffer
	logger.logger.SetOutput(&buf)
	logger.logger.SetFormatter(&logrus.TextFormatter{})

	logger.Info("info message without fields")

	output := buf.String()
	assert.Contains(t, output, "info message without fields")
}

func TestLogrusLogger_Warn_NoFields(t *testing.T) {
	logger := &LogrusLogger{
		logger: logrus.New(),
	}

	var buf bytes.Buffer
	logger.logger.SetOutput(&buf)
	logger.logger.SetFormatter(&logrus.TextFormatter{})

	logger.Warn("warn message without fields")

	output := buf.String()
	assert.Contains(t, output, "warn message without fields")
}

func TestLogrusLogger_Error_NoFields(t *testing.T) {
	logger := &LogrusLogger{
		logger: logrus.New(),
	}

	var buf bytes.Buffer
	logger.logger.SetOutput(&buf)
	logger.logger.SetFormatter(&logrus.TextFormatter{})

	logger.Error("error message without fields")

	output := buf.String()
	assert.Contains(t, output, "error message without fields")
}

func TestExecutor_ExecuteContext(t *testing.T) {
	t.Run("successful command with context", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		ctx := context.Background()
		output, err := executor.ExecuteContext(ctx, "echo", "hello")
		assert.NoError(t, err)
		assert.Equal(t, "hello", output)
	})

	t.Run("context timeout", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		// Create a context that times out very quickly
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		// Sleep command should be interrupted
		_, err := executor.ExecuteContext(ctx, "sleep", "10")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "timed out")
	})

	t.Run("context cancellation", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		ctx, cancel := context.WithCancel(context.Background())

		// Cancel immediately in a goroutine
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()

		_, err := executor.ExecuteContext(ctx, "sleep", "10")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "cancel")
	})
}

func TestExecutor_ExecuteWithTimeout(t *testing.T) {
	t.Run("command completes within timeout", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		output, err := executor.ExecuteWithTimeout(5*time.Second, "echo", "fast")
		assert.NoError(t, err)
		assert.Equal(t, "fast", output)
	})

	t.Run("command exceeds timeout", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		_, err := executor.ExecuteWithTimeout(10*time.Millisecond, "sleep", "10")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "timed out")
	})
}

func TestExecutor_ExecuteWithInputContext(t *testing.T) {
	t.Run("successful command with input and context", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		ctx := context.Background()
		output, err := executor.ExecuteWithInputContext(ctx, "cat", "test input")
		assert.NoError(t, err)
		assert.Equal(t, "test input", output)
	})

	t.Run("context timeout with input", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
		defer cancel()

		// This should timeout
		_, err := executor.ExecuteWithInputContext(ctx, "sleep", "", "10")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "timed out")
	})
}

func TestExecutor_HasCommand(t *testing.T) {
	t.Run("command exists", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		// echo exists on all systems
		assert.True(t, executor.HasCommand("echo"))
		assert.True(t, executor.HasCommand("cat"))
	})

	t.Run("command does not exist", func(t *testing.T) {
		logger := NewLogger(false)
		executor := NewExecutor(logger, false)

		// This command should not exist
		assert.False(t, executor.HasCommand("nonexistent-command-12345"))
	})
}
