package casbinjetstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/nats-io/nats.go"
)

const (
	// DefaultBucket is the default JetStream KV bucket for storing Casbin rules/policies.
	DefaultBucket = "casbin_rules"
)

// CasbinRule is used to determine which policy line to load.
type CasbinRule struct {
	PType string `json:"ptype"`
	V0    string `json:"v0,omitempty"`
	V1    string `json:"v1,omitempty"`
	V2    string `json:"v2,omitempty"`
	V3    string `json:"v3,omitempty"`
	V4    string `json:"v4,omitempty"`
	V5    string `json:"v5,omitempty"`
}

// Config represents the configuration for the NATS Jetstream adapter.
type Config struct {
	// URL is the NATS server URL (default: nats://127.0.0.1:4222)
	URL string
	// NATS client TLS configuration (optional)
	TLSConfig TLSConfig
	// Auth selects the authentication mechanism (mutually exclusive fields).
	Auth Auth
	// Bucket is the JetStream Key-Value bucket used to store Casbin rules/policies (default: "casbin_rules")
	Bucket string
	// Logger provides structured logging for the adapter (default: slog.Default())
	Logger *slog.Logger
	// Concurrency controls the maximum number of concurrent goroutines used when fetching or purging policies from the KV bucket (default: NumCPU() / 2)
	Concurrency int
	// RecreateOnSave determines whether the KV bucket is recreated instead of deleting all elements.
	RecreateOnSave bool
}

// Adapter represents the NATS Jetstream adapter for policy storage.
type Adapter struct {
	logger         *slog.Logger
	store          *store
	recreateOnSave bool
}

func (a *Adapter) Close() error {
	cleanup(a.store)
	return nil
}

var _ persist.BatchAdapter = &Adapter{}

// NewAdapter creates a new NATS Jetstream  adapter with the provided configuration.
func NewAdapter(config *Config) (*Adapter, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}
	if config.URL == "" {
		config.URL = nats.DefaultURL
	}
	if config.Bucket == "" {
		config.Bucket = DefaultBucket
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	if config.Concurrency == 0 {
		config.Concurrency = runtime.NumCPU() / 2
	}
	ctx := context.Background()
	s, err := newStore(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("failed to create store: %w", err)
	}
	a := &Adapter{
		logger:         config.Logger,
		store:          s,
		recreateOnSave: config.RecreateOnSave,
	}
	// Safety net: cleanup if caller forgets Close.
	runtime.AddCleanup(a, cleanup, s)
	return a, nil
}

func loadPolicyLine(line CasbinRule, model model.Model) error {
	var p = []string{line.PType, line.V0, line.V1, line.V2, line.V3, line.V4, line.V5}
	index := len(p) - 1
	for p[index] == "" {
		index--
	}
	index += 1
	p = p[:index]
	return persist.LoadPolicyArray(p, model)
}

func (a *Adapter) savePolicyLine(ptype string, rule []string) CasbinRule {
	line := CasbinRule{}
	line.PType = ptype
	if len(rule) > 0 {
		line.V0 = rule[0]
	}
	if len(rule) > 1 {
		line.V1 = rule[1]
	}
	if len(rule) > 2 {
		line.V2 = rule[2]
	}
	if len(rule) > 3 {
		line.V3 = rule[3]
	}
	if len(rule) > 4 {
		line.V4 = rule[4]
	}
	if len(rule) > 5 {
		line.V5 = rule[5]
	}
	return line
}

// LoadPolicy loads all policy rules from the storage.
func (a *Adapter) LoadPolicy(model model.Model) error {
	return a.LoadPolicyCtx(context.Background(), model)
}

func (a *Adapter) LoadPolicyCtx(ctx context.Context, model model.Model) error {
	defer logDuration(a.logger, "loading policies", time.Now())
	a.logger.Debug("loading policies")
	lines, err := a.store.GetAllPolicies(ctx)
	if err != nil {
		return err
	}
	a.logger.Info("loading policies count", slog.Int("count", len(lines)))
	for _, line := range lines {
		err := loadPolicyLine(line, model)
		if err != nil {
			return err
		}
	}
	return nil
}

// SavePolicy saves all policy rules to the storage.
func (a *Adapter) SavePolicy(model model.Model) error {
	return a.SavePolicyCtx(context.Background(), model)
}

// SavePolicyCtx saves policy to the storage.
func (a *Adapter) SavePolicyCtx(ctx context.Context, model model.Model) error {
	defer logDuration(a.logger, "saving policies", time.Now())
	a.logger.Info("saving policies")

	var err error
	if a.recreateOnSave {
		err = a.store.RecreateBucket(ctx)
		if err != nil {
			return err
		}
	} else {
		err = a.store.PurgeAllPolicies(ctx)
		if err != nil {
			return err
		}
	}

	for ptype, ast := range model["p"] {
		for _, rule := range ast.Policy {
			line := a.savePolicyLine(ptype, rule)
			err = a.store.CreatePolicy(ctx, line)
			if err != nil {
				return err
			}
		}
	}
	for ptype, ast := range model["g"] {
		for _, rule := range ast.Policy {
			line := a.savePolicyLine(ptype, rule)
			err = a.store.CreatePolicy(ctx, line)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// AddPolicy adds a policy rule to the storage.
func (a *Adapter) AddPolicy(sec string, ptype string, rule []string) error {
	return a.AddPolicyCtx(context.Background(), sec, ptype, rule)
}

// AddPolicies adds policy rules to the storage.
func (a *Adapter) AddPolicies(sec string, ptype string, rules [][]string) error {
	ctx := context.Background()
	for _, rule := range rules {
		err := a.AddPolicyCtx(ctx, sec, ptype, rule)
		if err != nil {
			return err
		}
	}
	return nil
}

// AddPolicyCtx adds a policy rule to the storage.
func (a *Adapter) AddPolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	return a.store.CreatePolicy(ctx, line)
}

// RemovePolicy removes a policy rule from the storage.
func (a *Adapter) RemovePolicy(sec string, ptype string, rule []string) error {
	return a.RemovePolicyCtx(context.Background(), sec, ptype, rule)
}

// RemovePolicies removes policy rules from the storage.
func (a *Adapter) RemovePolicies(sec string, ptype string, rules [][]string) error {
	ctx := context.Background()
	for _, rule := range rules {
		err := a.RemovePolicyCtx(ctx, sec, ptype, rule)
		if err != nil {
			return err
		}
	}
	return nil
}

// RemovePolicyCtx removes a policy rule from the storage.
func (a *Adapter) RemovePolicyCtx(ctx context.Context, sec string, ptype string, rule []string) error {
	line := a.savePolicyLine(ptype, rule)
	return a.store.PurgePolicy(ctx, line)
}

// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	return a.RemoveFilteredPolicyCtx(context.Background(), sec, ptype, fieldIndex, fieldValues...)
}

// RemoveFilteredPolicyCtx removes policy rules that match the filter from the storage.
func (a *Adapter) RemoveFilteredPolicyCtx(ctx context.Context, sec string, ptype string, fieldIndex int, fieldValues ...string) error {
	line := CasbinRule{}
	line.PType = ptype
	if fieldIndex == -1 {
		return a.store.PurgeFilteredPolicies(ctx, line)
	}
	err := a.checkQueryField(fieldValues)
	if err != nil {
		return err
	}
	if fieldIndex <= 0 && 0 < fieldIndex+len(fieldValues) {
		line.V0 = fieldValues[0-fieldIndex]
	}
	if fieldIndex <= 1 && 1 < fieldIndex+len(fieldValues) {
		line.V1 = fieldValues[1-fieldIndex]
	}
	if fieldIndex <= 2 && 2 < fieldIndex+len(fieldValues) {
		line.V2 = fieldValues[2-fieldIndex]
	}
	if fieldIndex <= 3 && 3 < fieldIndex+len(fieldValues) {
		line.V3 = fieldValues[3-fieldIndex]
	}
	if fieldIndex <= 4 && 4 < fieldIndex+len(fieldValues) {
		line.V4 = fieldValues[4-fieldIndex]
	}
	if fieldIndex <= 5 && 5 < fieldIndex+len(fieldValues) {
		line.V5 = fieldValues[5-fieldIndex]
	}
	return a.store.PurgeFilteredPolicies(ctx, line)
}

func (a *Adapter) checkQueryField(fieldValues []string) error {
	for _, fieldValue := range fieldValues {
		if fieldValue != "" {
			return nil
		}
	}
	return errors.New("the query field cannot all be empty strings")
}

func logDuration(logger *slog.Logger, name string, start time.Time) {
	logger.Info("finished "+name,
		slog.Duration("elapsed", time.Since(start)),
	)
}
