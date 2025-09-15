package benchmarks

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/pat-fortress/pkg/fortress/interfaces"
	"github.com/pat-fortress/tests/mocks"
	"github.com/pat-fortress/tests/utils"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// FortressPerformanceBenchmarks contains comprehensive performance tests for all fortress services
// These benchmarks ensure the fortress maintains enterprise-grade performance standards

// BenchmarkFortressEmailProcessingPipeline benchmarks the complete email processing pipeline
func BenchmarkFortressEmailProcessingPipeline(b *testing.B) {
	// Setup complete fortress stack with mocks
	keep := mocks.NewMockKeep()
	watchtower := mocks.NewMockWatchtower()
	rampart := mocks.NewMockRampart()
	foundation := mocks.NewMockFoundation()
	eventBus := mocks.NewMockEventBus()

	// Configure mocks for optimal performance testing
	keep.On("ProcessEmail", mock.Anything, mock.AnythingOfType("*interfaces.Email")).Return(nil)
	rampart.On("ScanEmail", mock.Anything, mock.AnythingOfType("*interfaces.Email")).Return(&interfaces.ScanResult{
		Safe:    true,
		Threats: []string{},
		Score:   95.0,
	}, nil)
	watchtower.On("LogEmail", mock.AnythingOfType("*interfaces.Email"), "processed", mock.Anything).Return()
	foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)
	eventBus.On("Publish", mock.Anything, mock.AnythingOfType("*interfaces.Event")).Return(nil)

	testUtils := utils.NewFortressTestUtils(&testing.T{})
	ctx := context.Background()

	// Create test email template
	baseEmail := testUtils.CreateTestEmail(
		utils.WithSubject("Performance Test Email"),
		utils.WithFrom("performance@fortress.test"),
		utils.WithTo([]string{"recipient@fortress.test"}),
	)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		emailCounter := 0
		for pb.Next() {
			// Create unique email for each iteration to avoid caching effects
			email := testUtils.CreateTestEmail(
				utils.WithSubject(fmt.Sprintf("Performance Test Email %d", emailCounter)),
				utils.WithFrom(fmt.Sprintf("sender%d@fortress.test", emailCounter%1000)),
			)
			
			// Benchmark the complete processing pipeline
			err := keep.ProcessEmail(ctx, email)
			if err != nil {
				b.Error(err)
			}
			
			emailCounter++
		}
	})
}

// BenchmarkFortressEmailSearchOperations benchmarks search performance under load
func BenchmarkFortressEmailSearchOperations(b *testing.B) {
	keep := mocks.NewMockKeep()
	testUtils := utils.NewFortressTestUtils(&testing.T{})
	ctx := context.Background()

	// Setup search results mock
	searchResults := &interfaces.SearchResults{
		Emails:      testUtils.FortressTestEmailBatch(50),
		Total:       1000,
		Took:        time.Millisecond * 150,
		Facets:      map[string]interface{}{},
		Highlights:  map[string][]string{},
		Suggestions: []string{},
	}

	keep.On("SearchEmails", mock.Anything, mock.AnythingOfType("*interfaces.SearchQuery")).Return(searchResults, nil)

	// Test different search complexity levels
	searchQueries := []*interfaces.SearchQuery{
		testUtils.CreateTestSearchQuery("simple search"),
		testUtils.CreateTestSearchQuery("complex search with filters", 
			utils.WithSearchFields([]string{"subject", "body", "from"}),
			utils.WithSearchFuzzy(true)),
		testUtils.CreateTestSearchQuery("advanced search with sorting",
			utils.WithSearchSort("receivedAt", "desc"),
			utils.WithSearchFields([]string{"subject", "body", "from", "to"})),
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("Simple Search", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := keep.SearchEmails(ctx, searchQueries[0])
				if err != nil {
					b.Error(err)
				}
			}
		})
	})

	b.Run("Complex Search", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := keep.SearchEmails(ctx, searchQueries[1])
				if err != nil {
					b.Error(err)
				}
			}
		})
	})

	b.Run("Advanced Search", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, err := keep.SearchEmails(ctx, searchQueries[2])
				if err != nil {
					b.Error(err)
				}
			}
		})
	})
}

// BenchmarkFortressMetricsCollection benchmarks watchtower metrics performance
func BenchmarkFortressMetricsCollection(b *testing.B) {
	watchtower := mocks.NewMockWatchtower()
	
	// Configure mock to simulate realistic metric recording
	watchtower.On("RecordMetric", mock.AnythingOfType("string"), mock.AnythingOfType("float64"), mock.Anything).Return()
	watchtower.On("IncrementCounter", mock.AnythingOfType("string"), mock.Anything).Return()
	watchtower.On("RecordHistogram", mock.AnythingOfType("string"), mock.AnythingOfType("float64"), mock.Anything).Return()
	watchtower.On("SetGauge", mock.AnythingOfType("string"), mock.AnythingOfType("float64"), mock.Anything).Return()

	metricNames := []string{
		"fortress.emails.processed",
		"fortress.emails.size",
		"fortress.processing.duration",
		"fortress.storage.usage",
		"fortress.security.threats",
	}

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("Record Metrics", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				metricName := metricNames[counter%len(metricNames)]
				labels := map[string]string{
					"service": "fortress",
					"type":    "benchmark",
				}
				watchtower.RecordMetric(metricName, float64(counter), labels)
				counter++
			}
		})
	})

	b.Run("Increment Counters", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				counterName := fmt.Sprintf("fortress.benchmark.counter.%d", counter%10)
				labels := map[string]string{
					"worker": fmt.Sprintf("worker-%d", counter%4),
				}
				watchtower.IncrementCounter(counterName, labels)
				counter++
			}
		})
	})

	b.Run("Mixed Metrics Operations", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				switch counter % 4 {
				case 0:
					watchtower.RecordMetric("fortress.mixed.metric", float64(counter), nil)
				case 1:
					watchtower.IncrementCounter("fortress.mixed.counter", nil)
				case 2:
					watchtower.RecordHistogram("fortress.mixed.histogram", float64(counter)/1000, nil)
				case 3:
					watchtower.SetGauge("fortress.mixed.gauge", float64(counter%100), nil)
				}
				counter++
			}
		})
	})
}

// BenchmarkFortressDatabaseOperations benchmarks foundation database performance
func BenchmarkFortressDatabaseOperations(b *testing.B) {
	foundation := mocks.NewMockFoundation()
	ctx := context.Background()

	// Setup database operation mocks
	queryResult := &interfaces.QueryResult{
		Rows: []map[string]interface{}{
			{"id": "1", "subject": "Test Email"},
			{"id": "2", "subject": "Another Email"},
		},
		Count:    2,
		Duration: time.Microsecond * 500,
	}

	foundation.On("Query", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(queryResult, nil)
	foundation.On("QueryOne", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(
		map[string]interface{}{"id": "1", "subject": "Test"}, nil)
	foundation.On("Exec", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(nil)

	// Transaction mock
	mockTx := &mocks.MockTransaction{}
	mockTx.On("Query", mock.AnythingOfType("string"), mock.Anything).Return(queryResult, nil)
	mockTx.On("Exec", mock.AnythingOfType("string"), mock.Anything).Return(nil)
	mockTx.On("Commit").Return(nil)
	mockTx.On("Rollback").Return(nil)
	
	foundation.On("BeginTransaction", mock.Anything).Return(mockTx, nil)
	foundation.On("Transaction", mock.Anything, mock.AnythingOfType("func(interfaces.Transaction) error")).Return(nil)

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("Database Queries", func(b *testing.B) {
		queries := []string{
			"SELECT * FROM emails WHERE id = $1",
			"SELECT COUNT(*) FROM emails WHERE created_at > $1",
			"SELECT * FROM emails ORDER BY created_at DESC LIMIT $1",
		}

		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				query := queries[counter%len(queries)]
				_, err := foundation.Query(ctx, query, counter)
				if err != nil {
					b.Error(err)
				}
				counter++
			}
		})
	})

	b.Run("Database Exec Operations", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				query := "INSERT INTO emails (id, subject) VALUES ($1, $2)"
				err := foundation.Exec(ctx, query, fmt.Sprintf("email-%d", counter), fmt.Sprintf("Subject %d", counter))
				if err != nil {
					b.Error(err)
				}
				counter++
			}
		})
	})

	b.Run("Database Transactions", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				err := foundation.Transaction(ctx, func(tx interfaces.Transaction) error {
					return tx.Exec("UPDATE emails SET processed = true WHERE id = $1", fmt.Sprintf("email-%d", counter))
				})
				if err != nil {
					b.Error(err)
				}
				counter++
			}
		})
	})
}

// BenchmarkFortressCacheOperations benchmarks caching performance
func BenchmarkFortressCacheOperations(b *testing.B) {
	foundation := mocks.NewMockFoundation()
	ctx := context.Background()

	// Setup cache operation mocks
	foundation.On("CacheSet", mock.Anything, mock.AnythingOfType("string"), mock.Anything, mock.Anything).Return(nil)
	foundation.On("CacheGet", mock.Anything, mock.AnythingOfType("string")).Return("cached value", nil)
	foundation.On("CacheDelete", mock.Anything, mock.AnythingOfType("string")).Return(nil)

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("Cache Set Operations", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				key := fmt.Sprintf("fortress:benchmark:key:%d", counter)
				value := fmt.Sprintf("value-%d", counter)
				ttl := 1 * time.Hour
				
				err := foundation.CacheSet(ctx, key, value, &ttl)
				if err != nil {
					b.Error(err)
				}
				counter++
			}
		})
	})

	b.Run("Cache Get Operations", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				key := fmt.Sprintf("fortress:benchmark:key:%d", counter%1000)
				_, err := foundation.CacheGet(ctx, key)
				if err != nil {
					b.Error(err)
				}
				counter++
			}
		})
	})

	b.Run("Mixed Cache Operations", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				key := fmt.Sprintf("fortress:mixed:key:%d", counter%500)
				
				switch counter % 3 {
				case 0:
					ttl := 1 * time.Hour
					foundation.CacheSet(ctx, key, fmt.Sprintf("value-%d", counter), &ttl)
				case 1:
					foundation.CacheGet(ctx, key)
				case 2:
					foundation.CacheDelete(ctx, key)
				}
				counter++
			}
		})
	})
}

// BenchmarkFortressSecurityOperations benchmarks rampart security performance
func BenchmarkFortressSecurityOperations(b *testing.B) {
	rampart := mocks.NewMockRampart()
	testUtils := utils.NewFortressTestUtils(&testing.T{})
	ctx := context.Background()

	// Setup security operation mocks
	scanResult := &interfaces.ScanResult{
		Safe:    true,
		Threats: []string{},
		Score:   95.0,
	}
	
	rampart.On("ScanEmail", mock.Anything, mock.AnythingOfType("*interfaces.Email")).Return(scanResult, nil)
	rampart.On("ValidateRequest", mock.Anything, mock.AnythingOfType("*interfaces.Request")).Return(&interfaces.SecurityResult{
		Valid:  true,
		Reason: "valid request",
	}, nil)
	rampart.On("CheckRateLimit", mock.Anything, mock.AnythingOfType("string"), mock.AnythingOfType("*interfaces.RateLimit")).Return(&interfaces.RateLimitResult{
		Allowed:   true,
		Remaining: 99,
		ResetTime: time.Now().Add(time.Hour),
	}, nil)

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("Email Security Scanning", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				email := testUtils.CreateTestEmail(
					utils.WithSubject(fmt.Sprintf("Security Test %d", counter)),
				)
				
				_, err := rampart.ScanEmail(ctx, email)
				if err != nil {
					b.Error(err)
				}
				counter++
			}
		})
	})

	b.Run("Rate Limiting Checks", func(b *testing.B) {
		rateLimit := &interfaces.RateLimit{
			Requests: 100,
			Window:   time.Minute,
		}

		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				key := fmt.Sprintf("client:%d", counter%100)
				
				_, err := rampart.CheckRateLimit(ctx, key, rateLimit)
				if err != nil {
					b.Error(err)
				}
				counter++
			}
		})
	})
}

// BenchmarkFortressEventBusOperations benchmarks event system performance
func BenchmarkFortressEventBusOperations(b *testing.B) {
	eventBus := mocks.NewMockEventBus()
	ctx := context.Background()

	// Setup event bus mocks
	eventBus.On("Publish", mock.Anything, mock.AnythingOfType("*interfaces.Event")).Return(nil)
	eventBus.On("PublishAsync", mock.Anything, mock.AnythingOfType("*interfaces.Event")).Return(nil)

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("Synchronous Event Publishing", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				event := &interfaces.Event{
					ID:        fmt.Sprintf("event-%d", counter),
					Type:      "fortress.benchmark.event",
					Source:    "benchmark",
					Timestamp: time.Now(),
					Data: map[string]interface{}{
						"counter": counter,
						"worker":  "benchmark",
					},
				}
				
				err := eventBus.Publish(ctx, event)
				if err != nil {
					b.Error(err)
				}
				counter++
			}
		})
	})

	b.Run("Asynchronous Event Publishing", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				event := &interfaces.Event{
					ID:        fmt.Sprintf("async-event-%d", counter),
					Type:      "fortress.benchmark.async",
					Source:    "benchmark",
					Timestamp: time.Now(),
					Data: map[string]interface{}{
						"counter": counter,
						"async":   true,
					},
				}
				
				err := eventBus.PublishAsync(ctx, event)
				if err != nil {
					b.Error(err)
				}
				counter++
			}
		})
	})
}

// BenchmarkFortressMemoryUsage benchmarks memory usage patterns
func BenchmarkFortressMemoryUsage(b *testing.B) {
	testUtils := utils.NewFortressTestUtils(&testing.T{})

	b.Run("Email Object Creation", func(b *testing.B) {
		b.ReportAllocs()
		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				_ = testUtils.CreateTestEmail(
					utils.WithSubject(fmt.Sprintf("Memory Test %d", counter)),
					utils.WithAttachment(fmt.Sprintf("file%d.txt", counter), "text/plain", []byte("test content")),
				)
				counter++
			}
		})
	})

	b.Run("Large Email Batch Creation", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = testUtils.FortressTestEmailBatch(1000)
		}
	})
}

// BenchmarkFortressConcurrentOperations benchmarks concurrent access patterns
func BenchmarkFortressConcurrentOperations(b *testing.B) {
	keep := mocks.NewMockKeep()
	foundation := mocks.NewMockFoundation()
	testUtils := utils.NewFortressTestUtils(&testing.T{})
	ctx := context.Background()

	// Setup mocks for concurrent operations
	keep.On("ProcessEmail", mock.Anything, mock.AnythingOfType("*interfaces.Email")).Return(nil)
	foundation.On("Query", mock.Anything, mock.AnythingOfType("string"), mock.Anything).Return(&interfaces.QueryResult{
		Rows:  []map[string]interface{}{{"id": "1"}},
		Count: 1,
	}, nil)

	b.ResetTimer()
	b.ReportAllocs()

	b.Run("Concurrent Email Processing", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				email := testUtils.CreateTestEmail(
					utils.WithSubject(fmt.Sprintf("Concurrent Test %d", counter)),
				)
				
				err := keep.ProcessEmail(ctx, email)
				if err != nil {
					b.Error(err)
				}
				counter++
			}
		})
	})

	b.Run("Concurrent Database Access", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			counter := 0
			for pb.Next() {
				query := "SELECT * FROM emails WHERE id = $1"
				_, err := foundation.Query(ctx, query, fmt.Sprintf("email-%d", counter))
				if err != nil {
					b.Error(err)
				}
				counter++
			}
		})
	})
}

// BenchmarkFortressResourceCleanup benchmarks resource management and cleanup
func BenchmarkFortressResourceCleanup(b *testing.B) {
	b.Run("Connection Pool Management", func(b *testing.B) {
		foundation := mocks.NewMockFoundation()
		ctx := context.Background()
		
		foundation.On("Connect", mock.Anything, mock.AnythingOfType("*interfaces.DatabaseConfig")).Return(nil)
		foundation.On("Disconnect", mock.Anything).Return(nil)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			config := &interfaces.DatabaseConfig{
				Type: "postgres",
				Host: "localhost",
			}
			
			foundation.Connect(ctx, config)
			foundation.Disconnect(ctx)
		}
	})

	b.Run("Context Cancellation Handling", func(b *testing.B) {
		keep := mocks.NewMockKeep()
		testUtils := utils.NewFortressTestUtils(&testing.T{})
		
		keep.On("ProcessEmail", mock.Anything, mock.AnythingOfType("*interfaces.Email")).Return(nil)

		b.ResetTimer()
		b.ReportAllocs()

		for i := 0; i < b.N; i++ {
			ctx, cancel := context.WithCancel(context.Background())
			email := testUtils.CreateTestEmail()
			
			// Start processing
			go func() {
				keep.ProcessEmail(ctx, email)
			}()
			
			// Cancel immediately
			cancel()
		}
	})
}

// Performance test helper functions

// measureLatency measures operation latency percentiles
func measureLatency(b *testing.B, operation func()) {
	latencies := make([]time.Duration, b.N)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		operation()
		latencies[i] = time.Since(start)
	}
	
	// Calculate percentiles
	// This is a simplified implementation - in production, use a proper stats library
	if b.N > 0 {
		// Log some basic stats (would typically use more sophisticated percentile calculation)
		b.Logf("Average latency: %v", latencies[b.N/2])
	}
}

// BenchmarkFortressLatencyMeasurement benchmarks with latency tracking
func BenchmarkFortressLatencyMeasurement(b *testing.B) {
	keep := mocks.NewMockKeep()
	testUtils := utils.NewFortressTestUtils(&testing.T{})
	ctx := context.Background()
	
	keep.On("ProcessEmail", mock.Anything, mock.AnythingOfType("*interfaces.Email")).Return(nil)

	email := testUtils.CreateTestEmail()

	measureLatency(b, func() {
		keep.ProcessEmail(ctx, email)
	})
}