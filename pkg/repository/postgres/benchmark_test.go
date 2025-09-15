package postgres_test

import (
	"context"
	"database/sql"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/pat/pkg/repository"
	"github.com/pat/pkg/repository/postgres"
)

// BenchmarkEmailRepository tests if we can achieve 10K writes/sec
func BenchmarkEmailRepository(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	// Setup database connection
	db, err := setupTestDB()
	require.NoError(b, err)
	defer db.Close()

	logger, _ := zap.NewDevelopment()
	repo := postgres.NewEmailRepository(db, logger)

	// Test data
	tenantID := uuid.New()
	emails := generateTestEmails(10000, tenantID)

	b.Run("Sequential_Writes", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			email := emails[i%len(emails)]
			email.ID = uuid.New()
			err := repo.Create(context.Background(), email)
			require.NoError(b, err)
		}
		b.StopTimer()
		
		writesPerSec := float64(b.N) / b.Elapsed().Seconds()
		b.ReportMetric(writesPerSec, "writes/sec")
	})

	b.Run("Concurrent_Writes", func(b *testing.B) {
		var wg sync.WaitGroup
		var successCount int64
		var errorCount int64
		
		workers := 50
		emailsPerWorker := b.N / workers
		
		b.ResetTimer()
		start := time.Now()
		
		for w := 0; w < workers; w++ {
			wg.Add(1)
			go func(workerID int) {
				defer wg.Done()
				
				for i := 0; i < emailsPerWorker; i++ {
					email := emails[(workerID*emailsPerWorker+i)%len(emails)]
					email.ID = uuid.New()
					
					err := repo.Create(context.Background(), email)
					if err != nil {
						atomic.AddInt64(&errorCount, 1)
					} else {
						atomic.AddInt64(&successCount, 1)
					}
				}
			}(w)
		}
		
		wg.Wait()
		b.StopTimer()
		
		elapsed := time.Since(start)
		writesPerSec := float64(successCount) / elapsed.Seconds()
		errorRate := float64(errorCount) / float64(successCount+errorCount) * 100
		
		b.ReportMetric(writesPerSec, "writes/sec")
		b.ReportMetric(errorRate, "error%")
		b.Logf("Concurrent writes: %.2f/sec, errors: %.2f%%", writesPerSec, errorRate)
	})

	b.Run("Batch_Writes", func(b *testing.B) {
		batchSize := 100
		batches := b.N / batchSize
		
		b.ResetTimer()
		start := time.Now()
		
		for i := 0; i < batches; i++ {
			tx, err := db.BeginTx(context.Background(), nil)
			require.NoError(b, err)
			
			for j := 0; j < batchSize; j++ {
				email := emails[(i*batchSize+j)%len(emails)]
				email.ID = uuid.New()
				
				_, err := tx.Exec(`
					INSERT INTO pat.emails (
						id, tenant_id, message_id, from_address, 
						to_addresses, subject, text_body, protocol, 
						status, created_at
					) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())`,
					email.ID, email.TenantID, email.MessageID,
					email.FromAddress, `[]`, email.Subject,
					email.TextBody, email.Protocol, email.Status,
				)
				require.NoError(b, err)
			}
			
			err = tx.Commit()
			require.NoError(b, err)
		}
		b.StopTimer()
		
		elapsed := time.Since(start)
		writesPerSec := float64(b.N) / elapsed.Seconds()
		b.ReportMetric(writesPerSec, "writes/sec")
		b.Logf("Batch writes: %.2f/sec", writesPerSec)
	})
}

// BenchmarkEmailReadLatency tests read latency
func BenchmarkEmailReadLatency(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping benchmark in short mode")
	}

	db, err := setupTestDB()
	require.NoError(b, err)
	defer db.Close()

	logger, _ := zap.NewDevelopment()
	repo := postgres.NewEmailRepository(db, logger)

	// Insert test data
	tenantID := uuid.New()
	emailIDs := make([]uuid.UUID, 1000)
	for i := 0; i < len(emailIDs); i++ {
		email := generateTestEmail(tenantID)
		err := repo.Create(context.Background(), email)
		require.NoError(b, err)
		emailIDs[i] = email.ID
	}

	b.Run("Get_By_ID", func(b *testing.B) {
		latencies := make([]time.Duration, 0, b.N)
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			emailID := emailIDs[i%len(emailIDs)]
			
			start := time.Now()
			_, err := repo.Get(context.Background(), emailID, tenantID)
			latency := time.Since(start)
			
			require.NoError(b, err)
			latencies = append(latencies, latency)
		}
		b.StopTimer()
		
		// Calculate percentiles
		p50 := calculatePercentile(latencies, 50)
		p95 := calculatePercentile(latencies, 95)
		p99 := calculatePercentile(latencies, 99)
		
		b.ReportMetric(float64(p50.Microseconds()), "p50_μs")
		b.ReportMetric(float64(p95.Microseconds()), "p95_μs")
		b.ReportMetric(float64(p99.Microseconds()), "p99_μs")
		b.Logf("Read latency - p50: %v, p95: %v, p99: %v", p50, p95, p99)
	})

	b.Run("List_Pagination", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			start := time.Now()
			
			result, err := repo.List(context.Background(), repository.QueryOptions{
				TenantID: tenantID,
				Limit:    100,
				Offset:   0,
				OrderBy:  "created_at",
				OrderDesc: true,
			})
			
			latency := time.Since(start)
			require.NoError(b, err)
			require.NotEmpty(b, result.Items)
			
			b.ReportMetric(float64(latency.Milliseconds()), "list_ms")
		}
	})

	b.Run("Full_Text_Search", func(b *testing.B) {
		searchTerms := []string{"test", "email", "subject", "important"}
		
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			searchTerm := searchTerms[i%len(searchTerms)]
			
			start := time.Now()
			result, err := repo.Search(context.Background(), searchTerm, repository.QueryOptions{
				TenantID: tenantID,
				Limit:    50,
				Offset:   0,
			})
			latency := time.Since(start)
			
			require.NoError(b, err)
			b.ReportMetric(float64(latency.Milliseconds()), "search_ms")
		}
	})
}

// Helper functions

func setupTestDB() (*sqlx.DB, error) {
	// Use environment variable or default
	dbURL := "postgres://patadmin:password@localhost:5432/pat_test?sslmode=disable"
	
	db, err := sqlx.Connect("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to test database: %w", err)
	}
	
	// Set connection pool settings for benchmarking
	db.SetMaxOpenConns(100)
	db.SetMaxIdleConns(50)
	db.SetConnMaxLifetime(5 * time.Minute)
	
	return db, nil
}

func generateTestEmails(count int, tenantID uuid.UUID) []*repository.Email {
	emails := make([]*repository.Email, count)
	for i := 0; i < count; i++ {
		emails[i] = generateTestEmail(tenantID)
	}
	return emails
}

func generateTestEmail(tenantID uuid.UUID) *repository.Email {
	subject := fmt.Sprintf("Test Email %s", uuid.New().String())
	return &repository.Email{
		ID:          uuid.New(),
		TenantID:    tenantID,
		MessageID:   fmt.Sprintf("<%s@test.example.com>", uuid.New().String()),
		FromAddress: "sender@example.com",
		ToAddresses: []repository.EmailAddress{
			{Address: "recipient@example.com"},
		},
		Subject:         &subject,
		TextBody:        stringPtr("This is a test email body for benchmarking."),
		Protocol:        "smtp",
		Status:          "received",
		AttachmentCount: 0,
		TotalSizeBytes:  1024,
		ReceivedAt:      time.Now(),
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}
}

func stringPtr(s string) *string {
	return &s
}

func calculatePercentile(latencies []time.Duration, percentile float64) time.Duration {
	if len(latencies) == 0 {
		return 0
	}
	
	// Simple percentile calculation (not exact but good enough for benchmarks)
	index := int(float64(len(latencies)) * percentile / 100)
	if index >= len(latencies) {
		index = len(latencies) - 1
	}
	
	return latencies[index]
}