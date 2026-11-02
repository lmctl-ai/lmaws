package host

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/sqs"

	"github.com/lmctl-ai/lmaws/internal/membudget"
)

func (h *Host) resolveQueueURLLocked(ctx context.Context, sqsClient *sqs.Client, queue string) (string, *CloudError) {
	out, err := sqsClient.GetQueueUrl(ctx, &sqs.GetQueueUrlInput{
		QueueName: aws.String(queue),
	})
	if err != nil {
		return "", classifyAWSError(err)
	}
	qURL := normalizeQueueURLToEndpoint(aws.ToString(out.QueueUrl), h.queueEndpoint)
	if qURL == "" {
		return "", newCloudError(CodeNotFound, 404, "AWS.SimpleQueueService.NonExistentQueue",
			fmt.Sprintf("queue %q does not exist", queue))
	}
	return qURL, nil
}

func (h *Host) QueueCreate(queue string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := ValidateQueueName(queue); cerr != nil {
		return false, h.finishErrorLocked("queue_create", queue, cerr)
	}
	if cerr := h.checkSimEndpointLocked(h.queueEndpoint); cerr != nil {
		return false, h.finishErrorLocked("queue_create", queue, cerr)
	}

	if h.queueEndpoint == "" {
		if _, exists := h.queues[queue]; exists {
			h.finishOKLocked()
			return false, nil
		}
		h.queues[queue] = &fakeQueue{name: queue}
		h.ledger.Record("queue", queue)
		h.finishOKLocked()
		return true, nil
	}

	ctx := context.Background()
	sqsClient := h.newSQSClientLocked()

	// Probe existence via GetQueueUrl first so queue_create returns false on existing queues.
	if _, cerr := h.resolveQueueURLLocked(ctx, sqsClient, queue); cerr == nil {
		h.finishOKLocked()
		return false, nil
	} else if cerr.Code != CodeNotFound {
		return false, h.finishErrorLocked("queue_create", queue, cerr)
	}

	out, err := sqsClient.CreateQueue(ctx, &sqs.CreateQueueInput{
		QueueName: aws.String(queue),
	})
	if err != nil {
		cerr := classifyAWSError(err)
		if cerr.Code == CodeAlreadyExists {
			h.finishOKLocked()
			return false, nil
		}
		return false, h.finishErrorLocked("queue_create", queue, cerr)
	}

	h.ledger.Record("queue", queue)
	_ = out
	h.finishOKLocked()
	return true, nil
}

func (h *Host) QueueDelete(queue string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := ValidateQueueName(queue); cerr != nil {
		return false, h.finishErrorLocked("queue_delete", queue, cerr)
	}
	if cerr := h.checkSimEndpointLocked(h.queueEndpoint); cerr != nil {
		return false, h.finishErrorLocked("queue_delete", queue, cerr)
	}

	if h.queueEndpoint == "" {
		if _, exists := h.queues[queue]; !exists {
			h.finishOKLocked()
			return false, nil
		}
		delete(h.queues, queue)
		h.ledger.Remove("queue", queue)
		h.finishOKLocked()
		return true, nil
	}

	ctx := context.Background()
	sqsClient := h.newSQSClientLocked()

	qURL, cerr := h.resolveQueueURLLocked(ctx, sqsClient, queue)
	if cerr != nil {
		if cerr.Code == CodeNotFound {
			h.finishOKLocked()
			return false, nil
		}
		return false, h.finishErrorLocked("queue_delete", queue, cerr)
	}

	_, delErr := sqsClient.DeleteQueue(ctx, &sqs.DeleteQueueInput{
		QueueUrl: aws.String(qURL),
	})
	if delErr != nil {
		delCerr := classifyAWSError(delErr)
		if delCerr.Code == CodeNotFound {
			h.finishOKLocked()
			return false, nil
		}
		return false, h.finishErrorLocked("queue_delete", queue, delCerr)
	}

	h.ledger.Remove("queue", queue)
	h.finishOKLocked()
	return true, nil
}

func (h *Host) QueueExists(queue string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := ValidateQueueName(queue); cerr != nil {
		return false, h.finishErrorLocked("queue_exists", queue, cerr)
	}
	if cerr := h.checkSimEndpointLocked(h.queueEndpoint); cerr != nil {
		return false, h.finishErrorLocked("queue_exists", queue, cerr)
	}

	if h.queueEndpoint == "" {
		_, exists := h.queues[queue]
		h.finishOKLocked()
		return exists, nil
	}

	ctx := context.Background()
	sqsClient := h.newSQSClientLocked()

	if _, cerr := h.resolveQueueURLLocked(ctx, sqsClient, queue); cerr != nil {
		if cerr.Code == CodeNotFound {
			h.finishOKLocked()
			return false, nil
		}
		return false, h.finishErrorLocked("queue_exists", queue, cerr)
	}

	h.finishOKLocked()
	return true, nil
}

func (h *Host) QueueList() ([]string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := h.checkSimEndpointLocked(h.queueEndpoint); cerr != nil {
		return nil, h.finishErrorLocked("queue_list", "", cerr)
	}

	if h.queueEndpoint == "" {
		names := make([]string, 0, len(h.queues))
		for name := range h.queues {
			names = append(names, name)
		}
		sort.Strings(names)
		h.finishOKLocked()
		return names, nil
	}

	ctx := context.Background()
	sqsClient := h.newSQSClientLocked()

	var names []string
	var nextToken *string
	for {
		out, err := sqsClient.ListQueues(ctx, &sqs.ListQueuesInput{
			NextToken: nextToken,
		})
		if err != nil {
			cerr := classifyAWSError(err)
			return nil, h.finishErrorLocked("queue_list", "", cerr)
		}
		for _, qURL := range out.QueueUrls {
			trimmed := strings.TrimRight(qURL, "/")
			if idx := strings.LastIndexByte(trimmed, '/'); idx >= 0 && idx+1 < len(trimmed) {
				names = append(names, trimmed[idx+1:])
			} else if trimmed != "" {
				names = append(names, trimmed)
			}
		}
		if out.NextToken == nil || *out.NextToken == "" {
			break
		}
		nextToken = out.NextToken
	}

	sort.Strings(names)
	h.finishOKLocked()
	return names, nil
}

func (h *Host) QueueSend(queue, body string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := ValidateQueueName(queue); cerr != nil {
		return "", h.finishErrorLocked("queue_send", queue, cerr)
	}
	if cerr := ValidateQueueBody(body); cerr != nil {
		return "", h.finishErrorLocked("queue_send", queue, cerr)
	}
	if cerr := h.checkSimEndpointLocked(h.queueEndpoint); cerr != nil {
		return "", h.finishErrorLocked("queue_send", queue, cerr)
	}

	if err := membudget.Charge(int64(len(body))); err != nil {
		return "", err
	}
	defer membudget.Release(int64(len(body)))

	wireBody := EncodeQueueBody(body)

	if h.queueEndpoint == "" {
		fq, exists := h.queues[queue]
		if !exists {
			return "", h.finishErrorLocked("queue_send", queue,
				newCloudError(CodeNotFound, 404, "AWS.SimpleQueueService.NonExistentQueue", fmt.Sprintf("queue %q does not exist", queue)))
		}
		fq.nextSeq++
		msgID := fmt.Sprintf("msg-%d", fq.nextSeq)
		fq.messages = append(fq.messages, &fakeQueueMessage{
			id:          msgID,
			wireBody:    wireBody,
			visibleAt:   time.Now(),
			firstEnqSeq: fq.nextSeq,
		})
		h.finishOKLocked()
		return msgID, nil
	}

	ctx := context.Background()
	sqsClient := h.newSQSClientLocked()

	qURL, cerr := h.resolveQueueURLLocked(ctx, sqsClient, queue)
	if cerr != nil {
		return "", h.finishErrorLocked("queue_send", queue, cerr)
	}

	out, err := sqsClient.SendMessage(ctx, &sqs.SendMessageInput{
		QueueUrl:    aws.String(qURL),
		MessageBody: aws.String(wireBody),
	})
	if err != nil {
		sendCerr := classifyAWSError(err)
		return "", h.finishErrorLocked("queue_send", queue, sendCerr)
	}

	msgID := aws.ToString(out.MessageId)
	if msgID == "" {
		msgID = "msg-1"
	}
	h.finishOKLocked()
	return msgID, nil
}

func (h *Host) QueueReceive(queue string, maxMessages, waitSeconds, visibilityTimeoutSeconds int64) (*QueueMessageList, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := ValidateQueueName(queue); cerr != nil {
		return nil, h.finishErrorLocked("queue_receive", queue, cerr)
	}
	if cerr := ValidateQueueReceiveParams(maxMessages, waitSeconds, visibilityTimeoutSeconds); cerr != nil {
		return nil, h.finishErrorLocked("queue_receive", queue, cerr)
	}
	if cerr := h.checkSimEndpointLocked(h.queueEndpoint); cerr != nil {
		return nil, h.finishErrorLocked("queue_receive", queue, cerr)
	}

	if h.queueEndpoint == "" {
		fq, exists := h.queues[queue]
		if !exists {
			return nil, h.finishErrorLocked("queue_receive", queue,
				newCloudError(CodeNotFound, 404, "AWS.SimpleQueueService.NonExistentQueue", fmt.Sprintf("queue %q does not exist", queue)))
		}
		deadline := time.Now().Add(time.Duration(waitSeconds) * time.Second)
		for {
			now := time.Now()
			var items []*QueueMessage
			for _, m := range fq.messages {
				if m.deleted || now.Before(m.visibleAt) {
					continue
				}
				m.receiptSeq++
				m.receipt = fmt.Sprintf("rcpt-%s-%d", m.id, m.receiptSeq)
				m.delivered = true
				m.visibleAt = now.Add(time.Duration(visibilityTimeoutSeconds) * time.Second)
				items = append(items, &QueueMessage{
					ID:      m.id,
					Body:    DecodeQueueBody(m.wireBody),
					Receipt: m.receipt,
				})
				if int64(len(items)) >= maxMessages {
					break
				}
			}
			if len(items) > 0 || waitSeconds == 0 || !time.Now().Before(deadline) {
				h.finishOKLocked()
				return &QueueMessageList{Items: items}, nil
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	ctx := context.Background()
	sqsClient := h.newSQSClientLocked()

	qURL, cerr := h.resolveQueueURLLocked(ctx, sqsClient, queue)
	if cerr != nil {
		return nil, h.finishErrorLocked("queue_receive", queue, cerr)
	}

	deadline := time.Now().Add(time.Duration(waitSeconds) * time.Second)
	for {
		remWait := int32(0)
		if waitSeconds > 0 {
			rem := time.Until(deadline)
			if rem > 0 {
				remWait = int32((rem + 999*time.Millisecond) / time.Second)
				if remWait > int32(waitSeconds) {
					remWait = int32(waitSeconds)
				}
			}
		}

		out, err := sqsClient.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{
			QueueUrl:            aws.String(qURL),
			MaxNumberOfMessages: int32(maxMessages),
			WaitTimeSeconds:     remWait,
			VisibilityTimeout:   int32(visibilityTimeoutSeconds),
		})
		if err != nil {
			recvCerr := classifyAWSError(err)
			return nil, h.finishErrorLocked("queue_receive", queue, recvCerr)
		}

		if len(out.Messages) > 0 || waitSeconds == 0 || !time.Now().Before(deadline) {
			items := make([]*QueueMessage, 0, len(out.Messages))
			for _, m := range out.Messages {
				items = append(items, &QueueMessage{
					ID:      aws.ToString(m.MessageId),
					Body:    DecodeQueueBody(aws.ToString(m.Body)),
					Receipt: aws.ToString(m.ReceiptHandle),
				})
			}
			h.finishOKLocked()
			return &QueueMessageList{Items: items}, nil
		}

		time.Sleep(100 * time.Millisecond)
	}
}

func (h *Host) QueueAck(queue, receipt string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := ValidateQueueName(queue); cerr != nil {
		return h.finishErrorLocked("queue_ack", queue, cerr)
	}
	if cerr := ValidateQueueReceipt(receipt); cerr != nil {
		return h.finishErrorLocked("queue_ack", queue, cerr)
	}
	if cerr := h.checkSimEndpointLocked(h.queueEndpoint); cerr != nil {
		return h.finishErrorLocked("queue_ack", queue, cerr)
	}

	if h.queueEndpoint == "" {
		fq, exists := h.queues[queue]
		if !exists {
			return h.finishErrorLocked("queue_ack", queue,
				newCloudError(CodeNotFound, 404, "AWS.SimpleQueueService.NonExistentQueue", fmt.Sprintf("queue %q does not exist", queue)))
		}
		for _, m := range fq.messages {
			if m.receipt == receipt {
				m.deleted = true
				break
			}
		}
		h.finishOKLocked()
		return nil
	}

	ctx := context.Background()
	sqsClient := h.newSQSClientLocked()

	qURL, cerr := h.resolveQueueURLLocked(ctx, sqsClient, queue)
	if cerr != nil {
		return h.finishErrorLocked("queue_ack", queue, cerr)
	}

	_, err := sqsClient.DeleteMessage(ctx, &sqs.DeleteMessageInput{
		QueueUrl:      aws.String(qURL),
		ReceiptHandle: aws.String(receipt),
	})
	if err != nil {
		ackCerr := classifyAWSError(err)
		// Duplicate DeleteMessage on an existing queue is idempotent (ErrorCode.OK).
		if ackCerr.HTTPStatus == 400 || ackCerr.HTTPStatus == 404 || ackCerr.Code == CodeInvalidArgument || ackCerr.Code == CodeNotFound {
			h.finishOKLocked()
			return nil
		}
		return h.finishErrorLocked("queue_ack", queue, ackCerr)
	}

	h.finishOKLocked()
	return nil
}

func (h *Host) QueueNack(queue, receipt string, visibilityTimeoutSeconds int64) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if cerr := ValidateQueueName(queue); cerr != nil {
		return "", h.finishErrorLocked("queue_nack", queue, cerr)
	}
	if cerr := ValidateQueueReceipt(receipt); cerr != nil {
		return "", h.finishErrorLocked("queue_nack", queue, cerr)
	}
	if cerr := ValidateQueueNackTimeout(visibilityTimeoutSeconds); cerr != nil {
		return "", h.finishErrorLocked("queue_nack", queue, cerr)
	}
	if cerr := h.checkSimEndpointLocked(h.queueEndpoint); cerr != nil {
		return "", h.finishErrorLocked("queue_nack", queue, cerr)
	}

	if h.queueEndpoint == "" {
		fq, exists := h.queues[queue]
		if !exists {
			return "", h.finishErrorLocked("queue_nack", queue,
				newCloudError(CodeNotFound, 404, "AWS.SimpleQueueService.NonExistentQueue", fmt.Sprintf("queue %q does not exist", queue)))
		}
		for _, m := range fq.messages {
			if !m.deleted && m.delivered && m.receipt == receipt {
				m.receiptSeq++
				m.receipt = fmt.Sprintf("rcpt-%s-%d", m.id, m.receiptSeq)
				m.visibleAt = time.Now().Add(time.Duration(visibilityTimeoutSeconds) * time.Second)
				h.finishOKLocked()
				return m.receipt, nil
			}
		}
		return "", h.finishErrorLocked("queue_nack", queue,
			newCloudError(CodeInvalidArgument, 400, "ReceiptHandleIsInvalid", "invalid or expired receipt handle"))
	}

	ctx := context.Background()
	sqsClient := h.newSQSClientLocked()

	qURL, cerr := h.resolveQueueURLLocked(ctx, sqsClient, queue)
	if cerr != nil {
		return "", h.finishErrorLocked("queue_nack", queue, cerr)
	}

	_, err := sqsClient.ChangeMessageVisibility(ctx, &sqs.ChangeMessageVisibilityInput{
		QueueUrl:          aws.String(qURL),
		ReceiptHandle:     aws.String(receipt),
		VisibilityTimeout: int32(visibilityTimeoutSeconds),
	})
	if err != nil {
		nackCerr := classifyAWSError(err)
		if nackCerr.HTTPStatus == 400 || nackCerr.HTTPStatus == 404 || nackCerr.Code == CodeNotFound {
			nackCerr = newCloudError(CodeInvalidArgument, nackCerr.HTTPStatus, nackCerr.ProviderCode, nackCerr.Message)
		}
		return "", h.finishErrorLocked("queue_nack", queue, nackCerr)
	}

	h.finishOKLocked()
	return receipt, nil
}
