package sync

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/zlovtnik/ssl-proxy/services/platform-sync/internal/log"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	lockName          = "platform-sync-lock"
	lockKey           = "heldBy"
	lockedAtKey       = "platform-sync/locked-at"
	lockTTLSecondsKey = "platform-sync/lock-ttl-seconds"
)

type Lock struct {
	namespace       string
	holder          string
	resourceVersion string
	expiresAt       time.Time
}

func acquireLock(ctx context.Context, logger *log.Logger, client objectClient, namespace string, ttlSeconds int, dryRun bool) (*Lock, error) {
	if ttlSeconds <= 0 || int64(ttlSeconds) > int64((1<<63-1)/time.Second) {
		return nil, fmt.Errorf("lock TTL is out of range")
	}
	existing, err := client.Get(ctx, configMapResource, namespace, lockName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("read pre-provisioned lock: %w", err)
	}

	now := time.Now().UTC()
	if active, holder, err := activeLock(existing, now); err != nil {
		return nil, err
	} else if active {
		return nil, fmt.Errorf("lock held by %s", holder)
	}

	holder := fmt.Sprintf("%s:%d", hostname(), os.Getpid())
	desired := existing.DeepCopy()
	annotations := desired.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[lockedAtKey] = now.Format(time.RFC3339Nano)
	annotations[lockTTLSecondsKey] = strconv.Itoa(ttlSeconds)
	desired.SetAnnotations(annotations)
	if err := unstructured.SetNestedField(desired.Object, holder, "data", lockKey); err != nil {
		return nil, fmt.Errorf("set lock holder: %w", err)
	}

	if _, err := client.Update(ctx, configMapResource, namespace, desired.DeepCopy(), metav1.UpdateOptions{
		FieldManager: fieldManager, DryRun: []string{metav1.DryRunAll},
	}); err != nil {
		return nil, fmt.Errorf("server-side dry-run lock: %w", err)
	}
	if dryRun {
		logger.Info("server-side dry-run accepted for lock")
		return nil, nil
	}
	expiresAt := now.Add(time.Duration(ttlSeconds) * time.Second)
	acquireCtx, cancel := context.WithDeadline(ctx, expiresAt.Add(-time.Duration(ttlSeconds)*time.Second/3))
	defer cancel()
	updated, err := client.Update(acquireCtx, configMapResource, namespace, desired, metav1.UpdateOptions{FieldManager: fieldManager})
	if err != nil {
		return nil, fmt.Errorf("update lock: %w", err)
	}
	logger.Info("acquired lock", "holder", holder)
	return &Lock{namespace: namespace, holder: holder, resourceVersion: updated.GetResourceVersion(), expiresAt: expiresAt}, nil
}

func activeLock(existing *unstructured.Unstructured, now time.Time) (bool, string, error) {
	holder, _, err := unstructured.NestedString(existing.Object, "data", lockKey)
	if err != nil {
		return false, "", fmt.Errorf("read lock holder: %w", err)
	}
	if holder == "" {
		return false, "", nil
	}
	annotations := existing.GetAnnotations()
	lockedAt, err := time.Parse(time.RFC3339Nano, annotations[lockedAtKey])
	if err != nil {
		return false, "", fmt.Errorf("lock has invalid acquisition time: %w", err)
	}
	ttlSeconds, err := strconv.Atoi(annotations[lockTTLSecondsKey])
	if err != nil || ttlSeconds <= 0 {
		return false, "", fmt.Errorf("lock has invalid TTL seconds %q", annotations[lockTTLSecondsKey])
	}
	return now.Before(lockedAt.Add(time.Duration(ttlSeconds) * time.Second)), holder, nil
}

func releaseLock(ctx context.Context, logger *log.Logger, client objectClient, lock *Lock) {
	if lock == nil {
		return
	}
	existing, err := client.Get(ctx, configMapResource, lock.namespace, lockName, metav1.GetOptions{})
	if err != nil {
		logger.Warn("failed to read lock for release", "error", err)
		return
	}
	holder, _, err := unstructured.NestedString(existing.Object, "data", lockKey)
	if err != nil || holder != lock.holder || existing.GetResourceVersion() != lock.resourceVersion {
		logger.Warn("lock changed since acquisition; skipping release")
		return
	}
	if err := unstructured.SetNestedField(existing.Object, "", "data", lockKey); err != nil {
		logger.Warn("failed to clear lock holder", "error", err)
		return
	}
	annotations := existing.GetAnnotations()
	delete(annotations, lockedAtKey)
	delete(annotations, lockTTLSecondsKey)
	existing.SetAnnotations(annotations)
	if _, err := client.Update(ctx, configMapResource, lock.namespace, existing, metav1.UpdateOptions{FieldManager: fieldManager}); err != nil {
		logger.Warn("failed to release lock", "error", err)
		return
	}
	logger.Info("released lock")
}

func hostname() string {
	host, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return host
}

var configMapResource = schema.GroupVersionResource{Group: "", Version: "v1", Resource: "configmaps"}
