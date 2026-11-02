package host

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	bucketNameRegex  = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	queueNameRegex   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,61}[a-z0-9]$`)
	metaKeyRegex     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
	ipv4LiteralRegex = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)
)

const (
	MaxObjectBodyBytes   = 32 * 1024 * 1024 // 32 MiB
	MaxQueuePayloadBytes = 49152            // 48 KiB
	EmptyQueueSentinel   = "__lmcloud_empty__"
	EscapedQueuePrefix   = "__lmcloud_esc__:"
	Base64QueuePrefix    = "__lmcloud_b64__:"
)

// ValidateServiceName validates the service selector passed to endpoint() / set_endpoint().
func ValidateServiceName(service string) *CloudError {
	switch service {
	case "", "storage", "object-storage", "object_storage", "s3", "blob", "gcs", "objectstorage", "sqs", "queue", "pubsub":
		return nil
	default:
		return newCloudError(CodeInvalidArgument, 0, "InvalidService",
			fmt.Sprintf("unsupported service selector %q", service))
	}
}

// ValidateEndpointURL validates the URL passed to set_endpoint(service, url).
// In SIM/FAKE ONLY mode, only loopback hosts (127.0.0.1, ::1, localhost) are accepted.
func ValidateEndpointURL(rawURL string) (string, *CloudError) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", newCloudError(CodeInvalidArgument, 0, "InvalidEndpoint",
			fmt.Sprintf("malformed endpoint URL %q", rawURL))
	}
	if u.User != nil {
		return "", newCloudError(CodeInvalidArgument, 0, "InvalidEndpoint",
			"endpoint URL must not contain userinfo credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", newCloudError(CodeInvalidArgument, 0, "InvalidEndpoint",
			"endpoint URL must not contain query string or fragment")
	}
	switch u.Scheme {
	case "http", "https":
		host := u.Hostname()
		if !isLoopbackHost(host) {
			return "", newCloudError(CodeInvalidArgument, 0, "InvalidEndpoint",
				fmt.Sprintf("non-loopback endpoint is not allowed (SIM/FAKE ONLY: only 127.0.0.1, ::1, localhost permitted); got %q", host))
		}
	default:
		return "", newCloudError(CodeInvalidArgument, 0, "InvalidEndpoint",
			fmt.Sprintf("endpoint scheme must be http or https; got %q", u.Scheme))
	}
	normalized := strings.TrimRight(u.String(), "/")
	return normalized, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// ValidateBucketName enforces the portable cross-provider bucket naming grammar.
func ValidateBucketName(bucket string) *CloudError {
	if len(bucket) < 3 || len(bucket) > 63 || !bucketNameRegex.MatchString(bucket) {
		return newCloudError(CodeInvalidArgument, 0, "InvalidBucketName",
			fmt.Sprintf("bucket name %q must be 3..63 chars matching ^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$", bucket))
	}
	if strings.Contains(bucket, "--") {
		return newCloudError(CodeInvalidArgument, 0, "InvalidBucketName",
			fmt.Sprintf("bucket name %q must not contain consecutive hyphens", bucket))
	}
	if ipv4LiteralRegex.MatchString(bucket) {
		return newCloudError(CodeInvalidArgument, 0, "InvalidBucketName",
			fmt.Sprintf("bucket name %q must not be formatted as an IPv4 address", bucket))
	}
	for _, reserved := range []string{"xn--", "sthree-", "amzn-s3-demo-", "goog"} {
		if strings.HasPrefix(bucket, reserved) {
			return newCloudError(CodeInvalidArgument, 0, "InvalidBucketName",
				fmt.Sprintf("bucket name %q uses reserved prefix %q", bucket, reserved))
		}
	}
	if strings.Contains(bucket, "google") || strings.Contains(bucket, "g00gle") {
		return newCloudError(CodeInvalidArgument, 0, "InvalidBucketName",
			fmt.Sprintf("bucket name %q contains reserved substring", bucket))
	}
	for _, suffix := range []string{"-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3"} {
		if strings.HasSuffix(bucket, suffix) {
			return newCloudError(CodeInvalidArgument, 0, "InvalidBucketName",
				fmt.Sprintf("bucket name %q uses reserved suffix %q", bucket, suffix))
		}
	}
	return nil
}

// ValidateObjectKey enforces portable object key constraints (including Azure-unsafe trailing dots and backslashes).
func ValidateObjectKey(key string) *CloudError {
	if len(key) == 0 || len(key) > 1024 {
		return newCloudError(CodeInvalidArgument, 0, "InvalidObjectKey",
			fmt.Sprintf("object key length must be 1..1024 UTF-8 bytes; got %d", len(key)))
	}
	if !utf8.ValidString(key) {
		return newCloudError(CodeInvalidArgument, 0, "InvalidObjectKey",
			"object key must be valid UTF-8")
	}
	if strings.HasPrefix(key, "/") {
		return newCloudError(CodeInvalidArgument, 0, "InvalidObjectKey",
			"object key must not start with '/'")
	}
	if strings.Contains(key, `\`) {
		return newCloudError(CodeInvalidArgument, 0, "InvalidObjectKey",
			`object key must not contain backslash '\'`)
	}
	for _, r := range key {
		if r <= 0x1F || r == 0x7F {
			return newCloudError(CodeInvalidArgument, 0, "InvalidObjectKey",
				"object key must not contain control characters (U+0000..U+001F or U+007F)")
		}
	}
	segments := strings.Split(key, "/")
	if len(segments) > 254 {
		return newCloudError(CodeInvalidArgument, 0, "InvalidObjectKey",
			fmt.Sprintf("object key has %d path segments (max 254)", len(segments)))
	}
	for _, seg := range segments {
		if seg == "" || seg == "." || seg == ".." || strings.HasSuffix(seg, ".") {
			return newCloudError(CodeInvalidArgument, 0, "InvalidObjectKey",
				fmt.Sprintf("object key contains invalid path segment %q", seg))
		}
	}
	return nil
}

// EncodeObjectKeyPath encodes each '/' segment so only RFC 3986 unreserved characters remain literal.
func EncodeObjectKeyPath(key string) string {
	segments := strings.Split(key, "/")
	out := make([]string, len(segments))
	for i, seg := range segments {
		out[i] = encodeRFC3986Unreserved(seg)
	}
	return strings.Join(out, "/")
}

func encodeRFC3986Unreserved(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	const hex = "0123456789ABCDEF"
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0F])
		}
	}
	return b.String()
}

// ValidateContentType enforces non-empty printable ASCII type/subtype without CR/LF.
func ValidateContentType(ct string) *CloudError {
	if len(ct) == 0 {
		return newCloudError(CodeInvalidArgument, 0, "InvalidContentType",
			"content_type must be non-empty")
	}
	for i := 0; i < len(ct); i++ {
		c := ct[i]
		if c < 0x20 || c > 0x7E {
			return newCloudError(CodeInvalidArgument, 0, "InvalidContentType",
				"content_type must contain only printable ASCII characters (0x20..0x7E) without CR/LF")
		}
	}
	slash := strings.IndexByte(ct, '/')
	if slash <= 0 || slash >= len(ct)-1 {
		return newCloudError(CodeInvalidArgument, 0, "InvalidContentType",
			fmt.Sprintf("content_type %q must be formatted as type/subtype", ct))
	}
	return nil
}

// ValidateMetadata enforces metadata key and value rules.
func ValidateMetadata(meta map[string]string) *CloudError {
	totalBytes := 0
	for k, v := range meta {
		if !metaKeyRegex.MatchString(k) {
			return newCloudError(CodeInvalidArgument, 0, "InvalidMetadataKey",
				fmt.Sprintf("metadata key %q must match ^[a-z][a-z0-9_]{0,62}$", k))
		}
		for i := 0; i < len(v); i++ {
			c := v[i]
			if c < 0x20 || c > 0x7E {
				return newCloudError(CodeInvalidArgument, 0, "InvalidMetadataValue",
					fmt.Sprintf("metadata value for key %q must be printable ASCII without CR/LF", k))
			}
		}
		totalBytes += len(k) + len(v)
	}
	if totalBytes > 2048 {
		return newCloudError(CodeInvalidArgument, 0, "MetadataTooLarge",
			fmt.Sprintf("total user metadata size %d exceeds 2048 bytes", totalBytes))
	}
	return nil
}

// ValidateListPrefix validates prefix for object_list / object_list_all.
func ValidateListPrefix(prefix string) *CloudError {
	if len(prefix) > 1024 || !utf8.ValidString(prefix) {
		return newCloudError(CodeInvalidArgument, 0, "InvalidPrefix",
			"prefix must be valid UTF-8 of at most 1024 bytes")
	}
	for _, r := range prefix {
		if r <= 0x1F || r == 0x7F {
			return newCloudError(CodeInvalidArgument, 0, "InvalidPrefix",
				"prefix must not contain control characters")
		}
	}
	return nil
}

// ValidateMaxKeys validates max_keys for object_list.
func ValidateMaxKeys(maxKeys int64) *CloudError {
	if maxKeys < 0 || maxKeys > 1000 {
		return newCloudError(CodeInvalidArgument, 0, "InvalidMaxKeys",
			fmt.Sprintf("max_keys must be in 0..1000; got %d", maxKeys))
	}
	return nil
}

// ValidateQueueName enforces portable queue naming constraints.
func ValidateQueueName(queue string) *CloudError {
	if len(queue) < 3 || len(queue) > 63 || !queueNameRegex.MatchString(queue) {
		return newCloudError(CodeInvalidArgument, 0, "InvalidQueueName",
			fmt.Sprintf("queue name %q must be 3..63 chars matching ^[a-z][a-z0-9-]{1,61}[a-z0-9]$", queue))
	}
	if strings.Contains(queue, "--") {
		return newCloudError(CodeInvalidArgument, 0, "InvalidQueueName",
			fmt.Sprintf("queue name %q must not contain consecutive hyphens", queue))
	}
	for _, reserved := range []string{"goog", "aws-", "amz-", "azure-", "xn--"} {
		if strings.HasPrefix(queue, reserved) {
			return newCloudError(CodeInvalidArgument, 0, "InvalidQueueName",
				fmt.Sprintf("queue name %q uses reserved prefix %q", queue, reserved))
		}
	}
	if strings.Contains(queue, "google") || strings.Contains(queue, "g00gle") {
		return newCloudError(CodeInvalidArgument, 0, "InvalidQueueName",
			fmt.Sprintf("queue name %q contains reserved substring", queue))
	}
	if strings.HasSuffix(queue, ".fifo") {
		return newCloudError(CodeInvalidArgument, 0, "InvalidQueueName",
			fmt.Sprintf("queue name %q uses reserved suffix .fifo", queue))
	}
	return nil
}

// ValidateQueueBody validates a queue message body before send.
func ValidateQueueBody(body string) *CloudError {
	if len(body) > MaxQueuePayloadBytes {
		return newCloudError(CodeInvalidArgument, 0, "MessageTooLarge",
			fmt.Sprintf("queue message body size %d exceeds 49152 bytes (48 KiB)", len(body)))
	}
	return nil
}

func needsBase64QueueEncoding(s string) bool {
	if !utf8.ValidString(s) {
		return true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7F {
			return true
		}
	}
	return false
}

// EncodeQueueBody encodes a logical body string into the wire representation.
func EncodeQueueBody(body string) string {
	if body == "" {
		return EmptyQueueSentinel
	}
	if needsBase64QueueEncoding(body) {
		return Base64QueuePrefix + base64.StdEncoding.EncodeToString([]byte(body))
	}
	if body == EmptyQueueSentinel ||
		strings.HasPrefix(body, EscapedQueuePrefix) ||
		strings.HasPrefix(body, Base64QueuePrefix) {
		return EscapedQueuePrefix + body
	}
	return body
}

// DecodeQueueBody decodes a wire representation back into the logical body string.
func DecodeQueueBody(wire string) string {
	if wire == EmptyQueueSentinel {
		return ""
	}
	if strings.HasPrefix(wire, EscapedQueuePrefix) {
		return strings.TrimPrefix(wire, EscapedQueuePrefix)
	}
	if strings.HasPrefix(wire, Base64QueuePrefix) {
		encoded := strings.TrimPrefix(wire, Base64QueuePrefix)
		if decoded, err := base64.StdEncoding.DecodeString(encoded); err == nil {
			return string(decoded)
		}
	}
	return wire
}

// ValidateQueueReceiveParams validates max_messages (1..10), wait_seconds (0..20), and visibility_timeout_seconds (0..600).
func ValidateQueueReceiveParams(maxMessages, waitSeconds, visibilityTimeoutSeconds int64) *CloudError {
	if maxMessages < 1 || maxMessages > 10 {
		return newCloudError(CodeInvalidArgument, 0, "InvalidMaxMessages",
			fmt.Sprintf("max_messages must be in 1..10; got %d", maxMessages))
	}
	if waitSeconds < 0 || waitSeconds > 20 {
		return newCloudError(CodeInvalidArgument, 0, "InvalidWaitSeconds",
			fmt.Sprintf("wait_seconds must be in 0..20; got %d", waitSeconds))
	}
	if visibilityTimeoutSeconds < 0 || visibilityTimeoutSeconds > 600 {
		return newCloudError(CodeInvalidArgument, 0, "InvalidVisibilityTimeout",
			fmt.Sprintf("visibility_timeout_seconds must be in 0..600; got %d", visibilityTimeoutSeconds))
	}
	return nil
}

// ValidateQueueReceipt validates a receipt token for queue_ack / queue_nack.
func ValidateQueueReceipt(receipt string) *CloudError {
	if strings.TrimSpace(receipt) == "" {
		return newCloudError(CodeInvalidArgument, 0, "InvalidReceipt",
			"receipt must be non-empty")
	}
	for _, r := range receipt {
		if r <= 0x1F || r == 0x7F {
			return newCloudError(CodeInvalidArgument, 0, "InvalidReceipt",
				"receipt must not contain control characters")
		}
	}
	return nil
}

// ValidateQueueNackTimeout validates visibility_timeout_seconds (0..600) for queue_nack.
func ValidateQueueNackTimeout(visibilityTimeoutSeconds int64) *CloudError {
	if visibilityTimeoutSeconds < 0 || visibilityTimeoutSeconds > 600 {
		return newCloudError(CodeInvalidArgument, 0, "InvalidVisibilityTimeout",
			fmt.Sprintf("visibility_timeout_seconds for queue_nack must be in 0..600; got %d", visibilityTimeoutSeconds))
	}
	return nil
}
