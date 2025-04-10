package trace

import (
	"context"
	"os"

	"github.com/sirupsen/logrus"
)

type contextKey int

const loggerKey contextKey = iota

func NewLogger(ctx context.Context) (context.Context, logrus.FieldLogger) {
	logger := logrus.New()
	logger.SetOutput(os.Stdout)
	logger.SetFormatter(&logrus.TextFormatter{
		DisableQuote: true},
	)
	logger.SetLevel(logrus.DebugLevel)
	entry := logger.WithContext(ctx)
	return context.WithValue(ctx, loggerKey, entry), entry
}

// Logger return the logger attached to context or the standard one.
func Logger(ctx context.Context) logrus.FieldLogger {
	logger, ok := ctx.Value(loggerKey).(logrus.FieldLogger)
	if !ok {
		_, logger = NewLogger(ctx)
	}
	return logger
}
