package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"

	"github.com/pat/pkg/repository"
)

// CacheRepository implements repository.CacheRepository using Redis
type CacheRepository struct {
	client *redis.ClusterClient
	logger *zap.Logger
	tracer trace.Tracer
	prefix string
}

// NewCacheRepository creates a new Redis cache repository
func NewCacheRepository(client *redis.ClusterClient, logger *zap.Logger, prefix string) *CacheRepository {
	return &CacheRepository{
		client: client,
		logger: logger,
		tracer: otel.Tracer("repository.redis.cache"),
		prefix: prefix,
	}
}

// Get retrieves a value by key
func (r *CacheRepository) Get(ctx context.Context, key string) ([]byte, error) {
	ctx, span := r.tracer.Start(ctx, "CacheRepository.Get")
	defer span.End()

	fullKey := r.prefixKey(key)
	span.SetAttributes(attribute.String("cache.key", fullKey))

	val, err := r.client.Get(ctx, fullKey).Bytes()
	if err != nil {
		if err == redis.Nil {
			span.SetAttributes(attribute.Bool("cache.hit", false))
			return nil, fmt.Errorf("key not found")
		}
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get value: %w", err)
	}

	span.SetAttributes(
		attribute.Bool("cache.hit", true),
		attribute.Int("cache.value_size", len(val)),
	)

	return val, nil
}

// Set stores a value with expiration
func (r *CacheRepository) Set(ctx context.Context, key string, value []byte, expiration time.Duration) error {
	ctx, span := r.tracer.Start(ctx, "CacheRepository.Set")
	defer span.End()

	fullKey := r.prefixKey(key)
	span.SetAttributes(
		attribute.String("cache.key", fullKey),
		attribute.Int("cache.value_size", len(value)),
		attribute.String("cache.ttl", expiration.String()),
	)

	err := r.client.Set(ctx, fullKey, value, expiration).Err()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to set value: %w", err)
	}

	return nil
}

// Delete removes a value
func (r *CacheRepository) Delete(ctx context.Context, key string) error {
	ctx, span := r.tracer.Start(ctx, "CacheRepository.Delete")
	defer span.End()

	fullKey := r.prefixKey(key)
	span.SetAttributes(attribute.String("cache.key", fullKey))

	err := r.client.Del(ctx, fullKey).Err()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to delete value: %w", err)
	}

	return nil
}

// Exists checks if a key exists
func (r *CacheRepository) Exists(ctx context.Context, key string) (bool, error) {
	ctx, span := r.tracer.Start(ctx, "CacheRepository.Exists")
	defer span.End()

	fullKey := r.prefixKey(key)
	span.SetAttributes(attribute.String("cache.key", fullKey))

	count, err := r.client.Exists(ctx, fullKey).Result()
	if err != nil {
		span.RecordError(err)
		return false, fmt.Errorf("failed to check existence: %w", err)
	}

	exists := count > 0
	span.SetAttributes(attribute.Bool("cache.exists", exists))

	return exists, nil
}

// GetMulti retrieves multiple values
func (r *CacheRepository) GetMulti(ctx context.Context, keys []string) (map[string][]byte, error) {
	ctx, span := r.tracer.Start(ctx, "CacheRepository.GetMulti")
	defer span.End()

	if len(keys) == 0 {
		return make(map[string][]byte), nil
	}

	// Prefix all keys
	fullKeys := make([]string, len(keys))
	keyMap := make(map[string]string) // full key -> original key
	for i, key := range keys {
		fullKey := r.prefixKey(key)
		fullKeys[i] = fullKey
		keyMap[fullKey] = key
	}

	span.SetAttributes(attribute.Int("cache.keys_count", len(keys)))

	// Use pipeline for efficiency
	pipe := r.client.Pipeline()
	cmds := make([]*redis.StringCmd, len(fullKeys))
	for i, key := range fullKeys {
		cmds[i] = pipe.Get(ctx, key)
	}

	_, err := pipe.Exec(ctx)
	if err != nil && err != redis.Nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to get multiple values: %w", err)
	}

	// Collect results
	result := make(map[string][]byte)
	hits := 0
	for i, cmd := range cmds {
		val, err := cmd.Bytes()
		if err == nil {
			originalKey := keyMap[fullKeys[i]]
			result[originalKey] = val
			hits++
		}
	}

	span.SetAttributes(
		attribute.Int("cache.hits", hits),
		attribute.Float64("cache.hit_rate", float64(hits)/float64(len(keys))),
	)

	return result, nil
}

// SetMulti stores multiple values
func (r *CacheRepository) SetMulti(ctx context.Context, items map[string][]byte, expiration time.Duration) error {
	ctx, span := r.tracer.Start(ctx, "CacheRepository.SetMulti")
	defer span.End()

	if len(items) == 0 {
		return nil
	}

	span.SetAttributes(
		attribute.Int("cache.items_count", len(items)),
		attribute.String("cache.ttl", expiration.String()),
	)

	// Use pipeline for efficiency
	pipe := r.client.Pipeline()
	for key, value := range items {
		fullKey := r.prefixKey(key)
		pipe.Set(ctx, fullKey, value, expiration)
	}

	_, err := pipe.Exec(ctx)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to set multiple values: %w", err)
	}

	return nil
}

// DeleteMulti removes multiple values
func (r *CacheRepository) DeleteMulti(ctx context.Context, keys []string) error {
	ctx, span := r.tracer.Start(ctx, "CacheRepository.DeleteMulti")
	defer span.End()

	if len(keys) == 0 {
		return nil
	}

	// Prefix all keys
	fullKeys := make([]string, len(keys))
	for i, key := range keys {
		fullKeys[i] = r.prefixKey(key)
	}

	span.SetAttributes(attribute.Int("cache.keys_count", len(keys)))

	err := r.client.Del(ctx, fullKeys...).Err()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to delete multiple values: %w", err)
	}

	return nil
}

// Increment increments a counter
func (r *CacheRepository) Increment(ctx context.Context, key string, delta int64) (int64, error) {
	ctx, span := r.tracer.Start(ctx, "CacheRepository.Increment")
	defer span.End()

	fullKey := r.prefixKey(key)
	span.SetAttributes(
		attribute.String("cache.key", fullKey),
		attribute.Int64("cache.delta", delta),
	)

	newVal, err := r.client.IncrBy(ctx, fullKey, delta).Result()
	if err != nil {
		span.RecordError(err)
		return 0, fmt.Errorf("failed to increment: %w", err)
	}

	span.SetAttributes(attribute.Int64("cache.new_value", newVal))

	return newVal, nil
}

// TTL gets the time-to-live for a key
func (r *CacheRepository) TTL(ctx context.Context, key string) (time.Duration, error) {
	ctx, span := r.tracer.Start(ctx, "CacheRepository.TTL")
	defer span.End()

	fullKey := r.prefixKey(key)
	span.SetAttributes(attribute.String("cache.key", fullKey))

	ttl, err := r.client.TTL(ctx, fullKey).Result()
	if err != nil {
		span.RecordError(err)
		return 0, fmt.Errorf("failed to get TTL: %w", err)
	}

	if ttl < 0 {
		return 0, fmt.Errorf("key does not exist or has no expiration")
	}

	span.SetAttributes(attribute.String("cache.ttl", ttl.String()))

	return ttl, nil
}

// Scan scans keys matching a pattern
func (r *CacheRepository) Scan(ctx context.Context, pattern string, count int) ([]string, error) {
	ctx, span := r.tracer.Start(ctx, "CacheRepository.Scan")
	defer span.End()

	fullPattern := r.prefixKey(pattern)
	span.SetAttributes(
		attribute.String("cache.pattern", fullPattern),
		attribute.Int("cache.count", count),
	)

	var cursor uint64
	var keys []string
	prefixLen := len(r.prefix + ":")

	// Scan across all cluster nodes
	err := r.client.ForEachShard(ctx, func(ctx context.Context, shard *redis.Client) error {
		for {
			var scanKeys []string
			var err error
			scanKeys, cursor, err = shard.Scan(ctx, cursor, fullPattern, int64(count)).Result()
			if err != nil {
				return err
			}

			// Remove prefix from keys
			for _, key := range scanKeys {
				if len(key) > prefixLen {
					keys = append(keys, key[prefixLen:])
				}
			}

			if cursor == 0 {
				break
			}
		}
		return nil
	})

	if err != nil {
		span.RecordError(err)
		return nil, fmt.Errorf("failed to scan keys: %w", err)
	}

	span.SetAttributes(attribute.Int("cache.keys_found", len(keys)))

	return keys, nil
}

// Helper methods

func (r *CacheRepository) prefixKey(key string) string {
	if r.prefix == "" {
		return key
	}
	return fmt.Sprintf("%s:%s", r.prefix, key)
}

// Warmup pre-loads frequently accessed data into cache
func (r *CacheRepository) Warmup(ctx context.Context, loader func(ctx context.Context) (map[string][]byte, error), expiration time.Duration) error {
	ctx, span := r.tracer.Start(ctx, "CacheRepository.Warmup")
	defer span.End()

	items, err := loader(ctx)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to load warmup data: %w", err)
	}

	if len(items) == 0 {
		return nil
	}

	err = r.SetMulti(ctx, items, expiration)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to warmup cache: %w", err)
	}

	span.SetAttributes(attribute.Int("cache.warmup_items", len(items)))
	r.logger.Info("Cache warmup completed",
		zap.Int("items", len(items)),
		zap.String("expiration", expiration.String()),
	)

	return nil
}

// InvalidatePattern invalidates all keys matching a pattern
func (r *CacheRepository) InvalidatePattern(ctx context.Context, pattern string) error {
	ctx, span := r.tracer.Start(ctx, "CacheRepository.InvalidatePattern")
	defer span.End()

	keys, err := r.Scan(ctx, pattern, 1000)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to scan for invalidation: %w", err)
	}

	if len(keys) == 0 {
		return nil
	}

	err = r.DeleteMulti(ctx, keys)
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to invalidate keys: %w", err)
	}

	span.SetAttributes(attribute.Int("cache.invalidated_count", len(keys)))
	r.logger.Info("Cache invalidation completed",
		zap.String("pattern", pattern),
		zap.Int("keys", len(keys)),
	)

	return nil
}