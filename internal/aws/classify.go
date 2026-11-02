// SPDX-License-Identifier: MIT

package aws

import (
	"errors"
	"net/http"
	"strings"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/smithy-go"
	"github.com/lmctl-ai/lmcloud/hostkit"
)

type scope int

const (
	scopeNone scope = iota
	scopeBucket
	scopeObject
	scopeQueue
	scopeMessage
)

// extractHTTPResponse inspects an AWS SDK v2 error chain for the underlying
// HTTP status code and headers.
func extractHTTPResponse(err error) (int, http.Header) {
	var respErr *awshttp.ResponseError
	if errors.As(err, &respErr) && respErr != nil {
		var hdr http.Header
		if httpResp := respErr.HTTPResponse(); httpResp != nil {
			hdr = httpResp.Header
		}
		return respErr.HTTPStatusCode(), hdr
	}
	return 0, nil
}

// cleanErrType trims optional ":..." suffixes and "namespace#" prefixes from
// X-Amzn-Errortype or Smithy error codes.
func cleanErrType(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.IndexByte(s, ':'); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if i := strings.LastIndexByte(s, '#'); i >= 0 {
		s = strings.TrimSpace(s[i+1:])
	}
	return s
}

// hasExplicitHeadAuthHeader reports whether err came from an HTTP response
// with an explicit X-Amzn-Errortype header that distinguishes UNAUTHENTICATED
// from PERMISSION_DENIED on a body-less HEAD 403.
func hasExplicitHeadAuthHeader(err error) bool {
	_, hdr := extractHTTPResponse(err)
	if hdr == nil {
		return false
	}
	switch cleanErrType(hdr.Get("X-Amzn-Errortype")) {
	case "InvalidAccessKeyId", "SignatureDoesNotMatch", "IncompleteSignature",
		"MissingAuthenticationToken", "ExpiredToken", "InvalidToken",
		"AccessDenied", "AccessDeniedException", "AllAccessDisabled":
		return true
	default:
		return false
	}
}

// classify maps an AWS S3 or SQS error onto one of the 8 shared hostkit.Code
// values and sets the appropriate hostkit.Absence qualifier.
func classify(err error, sc scope) *hostkit.CloudError {
	if err == nil {
		return nil
	}
	var ce *hostkit.CloudError
	if errors.As(err, &ce) {
		return ce
	}

	httpStatus, hdr := extractHTTPResponse(err)
	var headerErrType string
	if hdr != nil {
		headerErrType = cleanErrType(hdr.Get("X-Amzn-Errortype"))
	}

	var providerCode string
	msg := err.Error()
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) && apiErr != nil {
		providerCode = cleanErrType(apiErr.ErrorCode())
		if m := strings.TrimSpace(apiErr.ErrorMessage()); m != "" {
			msg = m
		}
	}

	// On HEAD responses without a body, aws-sdk-go-v2 synthesizes generic
	// status-derived codes ("Forbidden", "NotFound", "BadRequest", "Unauthorized").
	// Prefer a specific X-Amzn-Errortype header when present.
	if headerErrType != "" && (providerCode == "" ||
		providerCode == "Forbidden" ||
		providerCode == "NotFound" ||
		providerCode == "BadRequest" ||
		providerCode == "Unauthorized") {
		providerCode = headerErrType
	}
	if providerCode == "" && headerErrType != "" {
		providerCode = headerErrType
	}

	out := func(code hostkit.Code, absent hostkit.Absence) *hostkit.CloudError {
		return &hostkit.CloudError{
			Code:         code,
			Message:      msg,
			ProviderCode: providerCode,
			HTTPStatus:   httpStatus,
			Absent:       absent,
		}
	}

	switch providerCode {
	// 1. UNAUTHENTICATED
	case "InvalidAccessKeyId",
		"SignatureDoesNotMatch",
		"IncompleteSignature",
		"MissingAuthenticationToken",
		"ExpiredToken",
		"TokenRefreshRequired",
		"InvalidToken",
		"AuthFailure",
		"InvalidClientTokenId",
		"MissingClientTokenId",
		"UnrecognizedClientException",
		"Unauthorized",
		"NotAuthenticated":
		return out(hostkit.Unauthenticated, "")

	// 2. PERMISSION_DENIED
	case "AccessDenied",
		"AccessDeniedException",
		"AllAccessDisabled",
		"AccountProblem",
		"InvalidPayer",
		"NotSignedUp":
		return out(hostkit.PermissionDenied, "")

	// 3. NOT_FOUND (with resource-absence qualifiers)
	case "NoSuchBucket":
		return out(hostkit.NotFound, hostkit.AbsentBucket)
	case "NoSuchKey":
		return out(hostkit.NotFound, hostkit.AbsentObject)
	case "AWS.SimpleQueueService.NonExistentQueue",
		"QueueDoesNotExist",
		"NonExistentQueue",
		"ResourceNotFoundException":
		if sc == scopeBucket {
			return out(hostkit.NotFound, hostkit.AbsentBucket)
		}
		return out(hostkit.NotFound, hostkit.AbsentQueue)
	case "MessageNotInflight", "MessageDoesNotExist":
		return out(hostkit.NotFound, hostkit.AbsentMessage)
	case "NotFound":
		switch sc {
		case scopeBucket:
			return out(hostkit.NotFound, hostkit.AbsentBucket)
		case scopeObject:
			return out(hostkit.NotFound, hostkit.AbsentObject)
		case scopeQueue:
			return out(hostkit.NotFound, hostkit.AbsentQueue)
		case scopeMessage:
			return out(hostkit.NotFound, hostkit.AbsentMessage)
		default:
			return out(hostkit.NotFound, "")
		}

	// 4. CONFLICT (409 / bucket not empty / bucket already exists / queue deleted recently)
	case "BucketAlreadyExists",
		"BucketAlreadyOwnedByYou",
		"BucketNotEmpty",
		"QueueNameExists",
		"QueueAlreadyExists",
		"AWS.SimpleQueueService.QueueNameExists",
		"AWS.SimpleQueueService.QueueDeletedRecently",
		"QueueDeletedRecently",
		"OperationAborted",
		"ConditionalRequestConflict":
		return out(hostkit.Conflict, "")

	// 5. PRECONDITION_FAILED (412)
	case "PreconditionFailed":
		return out(hostkit.PreconditionFailed, "")

	// 6. INVALID_ARGUMENT (400 / invalid receipt handle / invalid parameters)
	case "ReceiptHandleIsInvalid",
		"InvalidParameterValue",
		"InvalidArgument",
		"InvalidBucketName",
		"InvalidRequest",
		"MalformedXML",
		"InvalidURI",
		"KeyTooLongError",
		"MetadataTooLarge",
		"EntityTooLarge",
		"EntityTooSmall",
		"InvalidAttributeName",
		"InvalidAttributeValue",
		"InvalidMessageContents",
		"BatchRequestTooLong",
		"EmptyBatchRequest",
		"TooManyEntriesInBatchRequest",
		"OverLimit":
		return out(hostkit.InvalidArgument, "")

	// 7. Rate-limit / 5xx after retry exhaustion -> INTERNAL
	case "SlowDown",
		"RequestThrottled",
		"Throttling",
		"ThrottlingException",
		"TooManyRequestsException",
		"InternalError",
		"ServiceUnavailable",
		"RequestTimeout":
		return out(hostkit.Internal, "")
	}

	switch {
	case httpStatus == 401:
		return out(hostkit.Unauthenticated, "")
	case httpStatus == 403 || providerCode == "Forbidden":
		return out(hostkit.PermissionDenied, "")
	case httpStatus == 404:
		switch sc {
		case scopeBucket:
			return out(hostkit.NotFound, hostkit.AbsentBucket)
		case scopeObject:
			return out(hostkit.NotFound, hostkit.AbsentObject)
		case scopeQueue:
			return out(hostkit.NotFound, hostkit.AbsentQueue)
		case scopeMessage:
			return out(hostkit.NotFound, hostkit.AbsentMessage)
		default:
			return out(hostkit.NotFound, "")
		}
	case httpStatus == 409:
		return out(hostkit.Conflict, "")
	case httpStatus == 412:
		return out(hostkit.PreconditionFailed, "")
	case httpStatus == 400:
		return out(hostkit.InvalidArgument, "")
	default:
		return out(hostkit.Internal, "")
	}
}
