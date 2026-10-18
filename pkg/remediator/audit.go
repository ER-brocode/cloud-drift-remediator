package remediator

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/ER-brocode/cloud-drift-remediator/pkg/model"
)

// AuditEvent represents an immutable record of an automated or manual remediation event.
type AuditEvent struct {
	EventID    string                      `json:"event_id"`
	Timestamp  time.Time                   `json:"timestamp"`
	PlanID     string                      `json:"plan_id,omitempty"`
	StepID     string                      `json:"step_id,omitempty"`
	ResourceID string                      `json:"resource_id"`
	Action     model.RemediationActionType `json:"action"`
	Status     model.RemediationStatus     `json:"status"`
	Details    string                      `json:"details,omitempty"`
}

// AuditLogger writes structured JSON audit trails for compliance.
type AuditLogger struct {
	filePath string
	mu       sync.Mutex
	events   []AuditEvent
}

// NewAuditLogger initializes an audit trail manager.
func NewAuditLogger(filePath string) *AuditLogger {
	return &AuditLogger{
		filePath: filePath,
		events:   make([]AuditEvent, 0),
	}
}

// LogEvent records a new event thread-safely in-memory and appends to disk if a path is configured.
func (l *AuditLogger) LogEvent(event AuditEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.events = append(l.events, event)

	if l.filePath != "" {
		data, err := json.Marshal(event)
		if err == nil {
			f, err := os.OpenFile(l.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err == nil {
				defer f.Close()
				_, _ = f.Write(append(data, '\n'))
			}
		}
	}
}

// GetEvents returns a snapshot copy of all recorded events.
func (l *AuditLogger) GetEvents() []AuditEvent {
	l.mu.Lock()
	defer l.mu.Unlock()
	copied := make([]AuditEvent, len(l.events))
	copy(copied, l.events)
	return copied
}

// PrintLog prints all audit records formatted.
func (l *AuditLogger) PrintLog() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	res := fmt.Sprintf("=== Audit Trail (%d events) ===\n", len(l.events))
	for _, e := range l.events {
		res += fmt.Sprintf("[%s] %s | %s | %s -> %s (%s)\n",
			e.Timestamp.Format(time.RFC3339), e.EventID, e.ResourceID, e.Action, e.Status, e.Details)
	}
	return res
}
