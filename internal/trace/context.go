package trace

import (
	"context"
	"io"

	"github.com/sirupsen/logrus"
)

type contextKey int

const loggerKey contextKey = iota

func NewLogger(ctx context.Context, out io.Writer) (context.Context, logrus.FieldLogger) {
	logger := logrus.New()
	logger.SetOutput(out)
	logger.SetFormatter(&Formatter{})
	logger.SetLevel(logrus.DebugLevel)
	entry := logger.WithContext(ctx)
	return context.WithValue(ctx, loggerKey, entry), entry
}

// Logger return the logger attached to context or the standard one.
func Logger(ctx context.Context) logrus.FieldLogger {
	logger, ok := ctx.Value(loggerKey).(logrus.FieldLogger)
	if !ok {
		return logrus.StandardLogger()
	}
	return logger
}
