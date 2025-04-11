package trace

import (
	"bytes"
	"fmt"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

type Formatter struct{}

// Format renders a single log entry.
func (f *Formatter) Format(entry *logrus.Entry) ([]byte, error) {
	timestamp := entry.Time.UTC().Format(time.RFC3339Nano)
	var level string
	switch entry.Level {
	case logrus.DebugLevel:
		level = "🔎"
	case logrus.InfoLevel:
		level = "ℹ️"
	case logrus.WarnLevel:
		level = "⚠️"
	case logrus.ErrorLevel:
		level = "❌"
	case logrus.FatalLevel:
		level = "💥"
	case logrus.PanicLevel:
		level = "😨"
	default:
		level = "❓"
	}

	message := entry.Message
	for _, emoji := range []string{"📤", "📥", "✅"} {
		if strings.HasPrefix(message, emoji+" ") {
			level = emoji
			message = message[len(emoji)+1:]
			break
		}
	}

	buf := bytes.NewBuffer(nil)
	fmt.Fprintf(buf, "[%s]\n%s %s\n", timestamp, level, message)
	return buf.Bytes(), nil
}
