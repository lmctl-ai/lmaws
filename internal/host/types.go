package host

import (
	"fmt"
	"strings"

	"github.com/lmctl-ai/lmaws/internal/safety"
)

const (
	CodeOK                 = "OK"
	CodeInvalidArgument    = "INVALID_ARGUMENT"
	CodeNotFound           = "NOT_FOUND"
	CodeAlreadyExists      = "ALREADY_EXISTS"
	CodeConflict           = "CONFLICT"
	CodeUnauthenticated    = "UNAUTHENTICATED"
	CodePermissionDenied   = "PERMISSION_DENIED"
	CodePreconditionFailed = "PRECONDITION_FAILED"
	CodeRateLimited        = "RATE_LIMITED"
	CodeUnavailable        = "UNAVAILABLE"
	CodeInternal           = "INTERNAL"
)

// CloudError holds structured diagnostic details for the most recent Cloud operation.
type CloudError struct {
	OK           bool
	Code         string
	HTTPStatus   int
	ProviderCode string
	Message      string
}

func okCloudError() *CloudError {
	return &CloudError{
		OK:           true,
		Code:         CodeOK,
		HTTPStatus:   0,
		ProviderCode: "",
		Message:      "",
	}
}

func newCloudError(code string, httpStatus int, providerCode, message string) *CloudError {
	if code == "" || code == CodeOK {
		code = CodeInternal
	}
	return &CloudError{
		OK:           false,
		Code:         code,
		HTTPStatus:   httpStatus,
		ProviderCode: safety.Redact(providerCode),
		Message:      safety.Redact(message),
	}
}

func (e *CloudError) FormatAbortError(op, target string) error {
	msg := safety.Redact(e.Message)
	pcode := safety.Redact(e.ProviderCode)
	return fmt.Errorf("[%s] %s (%s): %s (http=%d, provider_code=%s)", e.Code, op, target, msg, e.HTTPStatus, pcode)
}

// ObjectMeta holds normalized metadata for an object.
type ObjectMeta struct {
	Exists      bool
	Bucket      string
	Key         string
	Size        int64
	ETag        string
	ContentType string
	Metadata    map[string]string
}

func notFoundObjectMeta(bucket, key string) *ObjectMeta {
	return &ObjectMeta{
		Exists:      false,
		Bucket:      bucket,
		Key:         key,
		Size:        0,
		ETag:        "",
		ContentType: "",
		Metadata:    map[string]string{},
	}
}

// NormalizeETag strips optional weak prefix W/ and surrounding ASCII double quotes.
func NormalizeETag(raw string) string {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, "W/") || strings.HasPrefix(s, "w/") {
		s = strings.TrimSpace(s[2:])
	}
	if len(s) >= 2 && strings.HasPrefix(s, `"`) && strings.HasSuffix(s, `"`) {
		s = s[1 : len(s)-1]
	}
	return s
}

// ObjectSummary holds normalized summary metadata for an object in a list page.
type ObjectSummary struct {
	Key  string
	Size int64
	ETag string
}

// ObjectListPage holds a single lexicographically sorted page of objects.
type ObjectListPage struct {
	Items     []*ObjectSummary
	HasMore   bool
	NextToken string
}

func emptyObjectListPage() *ObjectListPage {
	return &ObjectListPage{
		Items:     []*ObjectSummary{},
		HasMore:   false,
		NextToken: "",
	}
}

// QueueMessage holds a single received queue message.
type QueueMessage struct {
	ID      string
	Body    string
	Receipt string
}

// QueueMessageList holds a batch of received queue messages.
type QueueMessageList struct {
	Items []*QueueMessage
}

func emptyQueueMessageList() *QueueMessageList {
	return &QueueMessageList{
		Items: []*QueueMessage{},
	}
}
