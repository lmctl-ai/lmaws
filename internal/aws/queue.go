// SPDX-License-Identifier: MIT

package aws

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/lmctl-ai/lmcloud/hostkit"
)

// createTokenTagKey is the SQS queue tag key where lmaws atomically stores
// hostkit.CreateToken(ctx) on CreateQueue requests so QueueCreateToken can
// prove ownership after a conflict (hostkit v3 risk 10).
const createTokenTagKey = "lmcloud-create-token"

func (r *remote) QueueCaps() hostkit.QueueCaps {
	return hostkit.QueueCaps{LongPoll: true, TextOnlyWire: true}
}

func (r *remote) resolveQueueURL(ctx context.Context, cli *sqs.Client, name string) (string, error) {
	var out *sqs.GetQueueUrlOutput
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		var gErr error
		out, gErr = cli.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{
			QueueName: aws.String(name),
		})
		return gErr
	})
	if err != nil {
		return "", classify(err, scopeQueue)
	}
	raw := strings.TrimSpace(aws.ToString(out.QueueUrl))
	if raw == "" {
		return "", &hostkit.CloudError{
			Code:    hostkit.Internal,
			Message: "sqs GetQueueUrl returned an empty QueueUrl",
		}
	}
	return normalizeQueueURLToEndpoint(raw, hostkit.EndpointFrom(ctx)), nil
}

// normalizeQueueURLToEndpoint rewrites the scheme and host of a QueueUrl
// returned by awssim to match the configured loopback endpoint.
func normalizeQueueURLToEndpoint(queueURL, endpoint string) string {
	qu, err1 := url.Parse(queueURL)
	eu, err2 := url.Parse(endpoint)
	if err1 != nil || err2 != nil || eu.Host == "" {
		return queueURL
	}
	qu.Scheme = eu.Scheme
	qu.Host = eu.Host
	return qu.String()
}

func queueNameFromURL(queueURL string) string {
	u, err := url.Parse(strings.TrimSpace(queueURL))
	path := queueURL
	if err == nil && u.Path != "" {
		path = u.Path
	}
	path = strings.TrimRight(path, "/")
	if idx := strings.LastIndexByte(path, '/'); idx >= 0 {
		return path[idx+1:]
	}
	return path
}

func (r *remote) CreateQueue(ctx context.Context, name string) (bool, error) {
	r.recordCall("CreateQueue", true)
	cli := r.sqsClient(ctx)
	tok := hostkit.CreateToken(ctx)

	// Probe GetQueueUrl first because SQS CreateQueue on an already-existing
	// queue with default attributes returns 200 OK instead of 400 QueueAlreadyExists.
	// When the queue already exists, report CONFLICT (or false when no token is
	// attached) so cloudhost resolves ownership via LookupQueue + QueueCreateToken.
	if _, err := r.resolveQueueURL(ctx, cli, name); err == nil {
		if tok == "" {
			return false, nil
		}
		return false, hostkit.ProviderError(hostkit.Conflict, http.StatusConflict, "QueueAlreadyExists", "queue already exists")
	} else if ce := classify(err, scopeQueue); ce.Code != hostkit.NotFound {
		return false, ce
	}

	in := &sqs.CreateQueueInput{
		QueueName: aws.String(name),
	}
	if tok != "" {
		in.Tags = map[string]string{createTokenTagKey: tok}
	}

	var out *sqs.CreateQueueOutput
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		var cErr error
		out, cErr = cli.CreateQueue(ctx, in)
		return cErr
	})
	if err != nil {
		return false, classify(err, scopeQueue)
	}
	if strings.TrimSpace(aws.ToString(out.QueueUrl)) == "" {
		return false, &hostkit.CloudError{
			Code:    hostkit.Internal,
			Message: "sqs CreateQueue returned an empty QueueUrl",
		}
	}
	return true, nil
}

func (r *remote) QueueCreateToken(ctx context.Context, name string) (string, error) {
	r.recordCall("QueueCreateToken", false)
	cli := r.sqsClient(ctx)
	qURL, err := r.resolveQueueURL(ctx, cli, name)
	if err != nil {
		return "", err
	}
	var out *sqs.ListQueueTagsOutput
	tErr := r.doAWS(ctx, true, func(ctx context.Context) error {
		var callErr error
		out, callErr = cli.ListQueueTags(ctx, &sqs.ListQueueTagsInput{
			QueueUrl: aws.String(qURL),
		})
		return callErr
	})
	if tErr != nil {
		return "", classify(tErr, scopeQueue)
	}
	if out == nil || len(out.Tags) == 0 {
		return "", nil
	}
	return strings.TrimSpace(out.Tags[createTokenTagKey]), nil
}

func (r *remote) DeleteQueue(ctx context.Context, name string) error {
	r.recordCall("DeleteQueue", true)
	cli := r.sqsClient(ctx)
	qURL, err := r.resolveQueueURL(ctx, cli, name)
	if err != nil {
		ce := classify(err, scopeQueue)
		if ce.Code == hostkit.NotFound {
			return ce.WithAbsent(hostkit.AbsentQueue)
		}
		return ce
	}
	dErr := r.doAWS(ctx, true, func(ctx context.Context) error {
		_, callErr := cli.DeleteQueue(ctx, &sqs.DeleteQueueInput{
			QueueUrl: aws.String(qURL),
		})
		return callErr
	})
	if dErr != nil {
		ce := classify(dErr, scopeQueue)
		if ce.Code == hostkit.NotFound {
			return ce.WithAbsent(hostkit.AbsentQueue)
		}
		return ce
	}
	return nil
}

func (r *remote) LookupQueue(ctx context.Context, name string) error {
	r.recordCall("LookupQueue", false)
	cli := r.sqsClient(ctx)
	_, err := r.resolveQueueURL(ctx, cli, name)
	if err == nil {
		return nil
	}
	ce := classify(err, scopeQueue)
	if ce.Code == hostkit.NotFound {
		return ce.WithAbsent(hostkit.AbsentQueue)
	}
	return ce
}

func (r *remote) ListQueues(ctx context.Context, token string) ([]string, string, error) {
	r.recordCall("ListQueues", false)
	cli := r.sqsClient(ctx)
	in := &sqs.ListQueuesInput{}
	if token != "" {
		in.NextToken = aws.String(token)
	}
	var out *sqs.ListQueuesOutput
	err := r.doAWS(ctx, true, func(ctx context.Context) error {
		var lErr error
		out, lErr = cli.ListQueues(ctx, in)
		return lErr
	})
	if err != nil {
		return nil, "", classify(err, scopeQueue)
	}
	names := make([]string, 0, len(out.QueueUrls))
	for _, u := range out.QueueUrls {
		if qName := queueNameFromURL(u); qName != "" {
			names = append(names, qName)
		}
	}
	return names, aws.ToString(out.NextToken), nil
}

func (r *remote) Send(ctx context.Context, queue, wire string) (string, error) {
	r.recordCall("Send", true)
	cli := r.sqsClient(ctx)
	qURL, err := r.resolveQueueURL(ctx, cli, queue)
	if err != nil {
		return "", err
	}
	var out *sqs.SendMessageOutput
	sErr := r.doAWS(ctx, false, func(ctx context.Context) error {
		var callErr error
		out, callErr = cli.SendMessage(ctx, &sqs.SendMessageInput{
			QueueUrl:    aws.String(qURL),
			MessageBody: aws.String(wire),
		})
		return callErr
	})
	if sErr != nil {
		return "", classify(sErr, scopeQueue)
	}
	id := strings.TrimSpace(aws.ToString(out.MessageId))
	if id == "" {
		return "", &hostkit.CloudError{
			Code:    hostkit.Internal,
			Message: "sqs SendMessage returned an empty MessageId",
		}
	}
	return id, nil
}

func (r *remote) Receive(ctx context.Context, queue string, max, waitSeconds, visibility int) ([]hostkit.RawMessage, error) {
	r.recordCall("Receive", false)
	cli := r.sqsClient(ctx)
	qURL, err := r.resolveQueueURL(ctx, cli, queue)
	if err != nil {
		return nil, err
	}

	deadline := time.Now().Add(time.Duration(waitSeconds) * time.Second)
	for {
		waitParam := int32(0)
		if waitSeconds > 0 {
			rem := time.Until(deadline)
			if rem > 0 {
				sec := int32((rem + 999*time.Millisecond) / time.Second)
				if sec > int32(waitSeconds) {
					sec = int32(waitSeconds)
				}
				if sec < 1 {
					sec = 1
				}
				waitParam = sec
			}
		}

		var out *sqs.ReceiveMessageOutput
		rErr := r.doAWS(ctx, false, func(ctx context.Context) error {
			var callErr error
			out, callErr = cli.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
				QueueUrl:            aws.String(qURL),
				MaxNumberOfMessages: int32(max),
				VisibilityTimeout:   int32(visibility),
				WaitTimeSeconds:     waitParam,
			})
			return callErr
		})
		if rErr != nil {
			return nil, classify(rErr, scopeQueue)
		}

		if len(out.Messages) > 0 {
			msgs := make([]hostkit.RawMessage, 0, len(out.Messages))
			for _, m := range out.Messages {
				id := aws.ToString(m.MessageId)
				rh := aws.ToString(m.ReceiptHandle)
				if id == "" || rh == "" {
					return nil, &hostkit.CloudError{
						Code:    hostkit.Internal,
						Message: "sqs ReceiveMessage entry missing MessageId or ReceiptHandle",
					}
				}
				msgs = append(msgs, hostkit.RawMessage{
					ID:      id,
					Wire:    aws.ToString(m.Body),
					Receipt: rh,
				})
			}
			return msgs, nil
		}

		if waitSeconds <= 0 || !time.Now().Before(deadline) {
			return []hostkit.RawMessage{}, nil
		}
		sleepDur := 50 * time.Millisecond
		if rem := time.Until(deadline); rem < sleepDur {
			sleepDur = rem
		}
		if sleepDur > 0 {
			select {
			case <-ctx.Done():
				return nil, classify(ctx.Err(), scopeQueue)
			case <-time.After(sleepDur):
			}
		}
	}
}

func (r *remote) Ack(ctx context.Context, queue, receipt string) error {
	r.recordCall("Ack", true)
	cli := r.sqsClient(ctx)
	qURL, err := r.resolveQueueURL(ctx, cli, queue)
	if err != nil {
		return err
	}
	dErr := r.doAWS(ctx, true, func(ctx context.Context) error {
		_, callErr := cli.DeleteMessage(ctx, &sqs.DeleteMessageInput{
			QueueUrl:      aws.String(qURL),
			ReceiptHandle: aws.String(receipt),
		})
		return callErr
	})
	if dErr != nil {
		return classify(dErr, scopeMessage)
	}
	return nil
}

func (r *remote) Nack(ctx context.Context, queue, receipt string, visibility int) (string, error) {
	r.recordCall("Nack", true)
	cli := r.sqsClient(ctx)
	qURL, err := r.resolveQueueURL(ctx, cli, queue)
	if err != nil {
		return "", err
	}
	cErr := r.doAWS(ctx, true, func(ctx context.Context) error {
		_, callErr := cli.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
			QueueUrl:          aws.String(qURL),
			ReceiptHandle:     aws.String(receipt),
			VisibilityTimeout: int32(visibility),
		})
		return callErr
	})
	if cErr != nil {
		return "", classify(cErr, scopeMessage)
	}
	return receipt, nil
}
