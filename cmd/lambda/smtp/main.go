package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sqs"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pat/pkg/events"
	eventsv1 "github.com/pat/api/events/v1"
	"github.com/pat/pkg/smtp"
)

var (
	logger       *zap.Logger
	s3Client     *s3.S3
	sqsClient    *sqs.SQS
	producer     *events.Producer
	smtpConfig   *smtp.Config
	handlerPool  sync.Pool
)

func init() {
	// Initialize logger
	logger, _ = zap.NewProduction()

	// Initialize AWS clients
	sess := session.Must(session.NewSession())
	s3Client = s3.New(sess)
	sqsClient = sqs.New(sess)

	// Initialize event producer
	kafkaBrokers := os.Getenv("KAFKA_BROKERS")
	if kafkaBrokers != "" {
		producerConfig := events.ProducerConfig{
			Brokers:          []string{kafkaBrokers},
			Topic:            os.Getenv("KAFKA_TOPIC"),
			CompressionType:  "lz4",
			IdempotenceEnable: true,
		}
		producer, _ = events.NewProducer(producerConfig, logger)
	}

	// Initialize SMTP config
	smtpConfig = &smtp.Config{
		Hostname:       os.Getenv("SMTP_HOSTNAME"),
		MaxMessageSize: 50 * 1024 * 1024, // 50MB
		MaxRecipients:  100,
		RequireAuth:    os.Getenv("SMTP_REQUIRE_AUTH") == "true",
		RequireTLS:     os.Getenv("SMTP_REQUIRE_TLS") == "true",
		Extensions: []smtp.Extension{
			smtp.ExtensionStartTLS,
			smtp.ExtensionAuth,
			smtp.ExtensionPipelining,
			smtp.Extension8BitMIME,
			smtp.ExtensionSize,
			smtp.ExtensionEnhancedCodes,
		},
		AuthMechanisms: []string{"PLAIN", "LOGIN"},
		ReadTimeout:    5 * time.Minute,
		WriteTimeout:   30 * time.Second,
		DataTimeout:    10 * time.Minute,
	}

	// Initialize handler pool
	handlerPool = sync.Pool{
		New: func() interface{} {
			return &lambdaMessageHandler{
				s3Bucket:  os.Getenv("S3_BUCKET"),
				sqsQueue:  os.Getenv("SQS_QUEUE_URL"),
				tenantID:  os.Getenv("TENANT_ID"),
			}
		},
	}
}

// LambdaEvent represents the event from NLB
type LambdaEvent struct {
	Connection ConnectionInfo `json:"connection"`
	Data       []byte         `json:"data"`
	SessionID  string         `json:"sessionId"`
}

// ConnectionInfo contains connection metadata
type ConnectionInfo struct {
	SourceIP   string `json:"sourceIp"`
	SourcePort int    `json:"sourcePort"`
	DestIP     string `json:"destIp"`
	DestPort   int    `json:"destPort"`
}

// lambdaMessageHandler implements smtp.MessageHandler
type lambdaMessageHandler struct {
	s3Bucket  string
	sqsQueue  string
	tenantID  string
}

// ValidateFrom validates the sender address
func (h *lambdaMessageHandler) ValidateFrom(session *smtp.Session, from string) error {
	// Basic validation - in production, add SPF/DKIM checks
	if from == "" {
		return nil // Allow null sender for bounces
	}

	// Check if sender is authorized
	if session.Authenticated && session.AuthUser != from {
		// In production, check if user can send as this address
	}

	return nil
}

// ValidateRecipient validates the recipient address
func (h *lambdaMessageHandler) ValidateRecipient(session *smtp.Session, to string) error {
	// In production, validate recipient exists and can receive mail
	// For now, accept all recipients
	return nil
}

// HandleMessage processes the received email
func (h *lambdaMessageHandler) HandleMessage(session *smtp.Session, envelope smtp.Envelope) error {
	ctx := context.Background()
	emailID := uuid.New().String()

	logger.Info("Processing email",
		zap.String("email_id", emailID),
		zap.String("from", envelope.From),
		zap.Int("recipients", len(envelope.Recipients)),
		zap.Int("size", len(envelope.Data)),
	)

	// Store raw email in S3
	s3Key := fmt.Sprintf("emails/%s/%s/raw.eml", h.tenantID, emailID)
	_, err := s3Client.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket:               aws.String(h.s3Bucket),
		Key:                  aws.String(s3Key),
		Body:                 aws.ReadSeekCloser(aws.ReadSeekCloserFromBytes(envelope.Data)),
		ContentType:          aws.String("message/rfc822"),
		ServerSideEncryption: aws.String("AES256"),
		Metadata: map[string]*string{
			"email-id":    aws.String(emailID),
			"from":        aws.String(envelope.From),
			"message-id":  aws.String(envelope.MessageID),
			"received-at": aws.String(envelope.Received.Format(time.RFC3339)),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to store email in S3: %w", err)
	}

	// Parse email headers and body
	headers := make(map[string]string)
	for key, values := range envelope.Headers {
		if len(values) > 0 {
			headers[key] = values[0]
		}
	}

	// Extract subject
	subject := headers["Subject"]
	
	// Create EmailReceived event
	event := &eventsv1.EmailReceived{
		EmailId:   emailID,
		MessageId: envelope.MessageID,
		From: &eventsv1.EmailAddress{
			Address: envelope.From,
		},
		Subject:    subject,
		RawEmail:   s3Key,
		Protocol:   "smtp",
		SourceIp:   session.RemoteAddr,
		ReceivedAt: timestamppb.New(envelope.Received),
		SizeBytes:  int64(len(envelope.Data)),
	}

	// Convert recipients
	for _, recipient := range envelope.Recipients {
		event.To = append(event.To, &eventsv1.EmailAddress{
			Address: recipient,
		})
	}

	// Send event to Kafka
	if producer != nil {
		if err := producer.SendEmailReceived(ctx, event); err != nil {
			logger.Error("Failed to send event to Kafka", zap.Error(err))
			// Fall back to SQS
		}
	}

	// Also send to SQS for redundancy
	sqsMessage := map[string]interface{}{
		"emailId":    emailID,
		"tenantId":   h.tenantID,
		"s3Key":      s3Key,
		"from":       envelope.From,
		"recipients": envelope.Recipients,
		"size":       len(envelope.Data),
		"receivedAt": envelope.Received,
	}

	messageBody, _ := json.Marshal(sqsMessage)
	_, err = sqsClient.SendMessage(&sqs.SendMessageInput{
		QueueUrl:    aws.String(h.sqsQueue),
		MessageBody: aws.String(string(messageBody)),
		MessageAttributes: map[string]*sqs.MessageAttributeValue{
			"emailId": {
				DataType:    aws.String("String"),
				StringValue: aws.String(emailID),
			},
			"tenantId": {
				DataType:    aws.String("String"),
				StringValue: aws.String(h.tenantID),
			},
		},
	})
	if err != nil {
		logger.Error("Failed to send message to SQS", zap.Error(err))
	}

	logger.Info("Email processed successfully",
		zap.String("email_id", emailID),
		zap.String("s3_key", s3Key),
	)

	return nil
}

// HandleRequest processes Lambda invocations
func HandleRequest(ctx context.Context, event LambdaEvent) error {
	logger.Info("Processing SMTP Lambda event",
		zap.String("session_id", event.SessionID),
		zap.String("source_ip", event.Connection.SourceIP),
		zap.Int("data_size", len(event.Data)),
	)

	// Create virtual connection from event data
	conn := newVirtualConn(event.Connection, event.Data)
	defer conn.Close()

	// Get handler from pool
	handler := handlerPool.Get().(*lambdaMessageHandler)
	defer handlerPool.Put(handler)

	// Create SMTP parser
	parser := smtp.NewParser(conn, smtpConfig, handler, logger)

	// Handle SMTP session
	if err := parser.Handle(); err != nil {
		logger.Error("SMTP session error", zap.Error(err))
		return err
	}

	return nil
}

// virtualConn implements net.Conn for Lambda processing
type virtualConn struct {
	data       []byte
	readIndex  int
	localAddr  net.Addr
	remoteAddr net.Addr
	closed     bool
	mu         sync.Mutex
}

func newVirtualConn(info ConnectionInfo, data []byte) *virtualConn {
	return &virtualConn{
		data:       data,
		localAddr:  &net.TCPAddr{IP: net.ParseIP(info.DestIP), Port: info.DestPort},
		remoteAddr: &net.TCPAddr{IP: net.ParseIP(info.SourceIP), Port: info.SourcePort},
	}
}

func (c *virtualConn) Read(b []byte) (n int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, net.ErrClosed
	}

	if c.readIndex >= len(c.data) {
		return 0, io.EOF
	}

	n = copy(b, c.data[c.readIndex:])
	c.readIndex += n
	return n, nil
}

func (c *virtualConn) Write(b []byte) (n int, err error) {
	// In Lambda context, we buffer writes to response
	// This would be sent back through the response channel
	return len(b), nil
}

func (c *virtualConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

func (c *virtualConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *virtualConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *virtualConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *virtualConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *virtualConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func main() {
	lambda.Start(HandleRequest)
}