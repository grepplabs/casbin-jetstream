package casbinjetstream

import (
	"log"
	"log/slog"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	fileadapter "github.com/casbin/casbin/v2/persist/file-adapter"
	"github.com/casbin/casbin/v2/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLoad(t *testing.T) {
	adapter, err := NewAdapter(&Config{
		Logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
	})
	require.Nil(t, err)

	_, err = casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	require.Nil(t, err)
}

func TestExample(t *testing.T) {
	srcAdapter := fileadapter.NewAdapter("examples/rbac_policy.csv")
	m, err := model.NewModelFromFile("examples/rbac_model.conf")
	require.Nil(t, err)

	err = srcAdapter.LoadPolicy(m)
	require.Nil(t, err)

	adapter, err := NewAdapter(&Config{
		Logger: slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
			Level: slog.LevelInfo,
		})),
		Concurrency: runtime.NumCPU(),
	})
	require.Nil(t, err)
	defer adapter.Close()

	err = adapter.SavePolicy(m)
	require.Nil(t, err)

	_, err = casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	require.Nil(t, err)

	m, err = model.NewModelFromFile("examples/rbac_model.conf")
	require.Nil(t, err)

	err = adapter.LoadPolicy(m)
	require.Nil(t, err)
}

func testGetPolicy(t *testing.T, e *casbin.Enforcer, res [][]string) {
	myRes, err := e.GetPolicy()
	if err != nil {
		panic(err)
	}

	log.Print("Policy: ", myRes)

	if !util.Array2DEquals(res, myRes) {
		t.Error("Policy: ", myRes, ", supposed to be ", res)
	}
}

func initPolicy(t *testing.T, a *Adapter) {
	// Because the DB is empty at first,
	// so we need to load the policy from the file adapter (.CSV) first.
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		panic(err)
	}

	// This is a trick to save the current policy to the DB.
	// We can't call e.SavePolicy() because the adapter in the enforcer is still the file adapter.
	// The current policy means the policy in the Casbin enforcer (aka in memory).
	err = a.SavePolicy(e.GetModel())
	if err != nil {
		panic(err)
	}

	// Clear the current policy.
	e.ClearPolicy()
	testGetPolicy(t, e, [][]string{})

	// Load the policy from DB.
	err = a.LoadPolicy(e.GetModel())
	if err != nil {
		panic(err)
	}
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}

func testSaveLoad(t *testing.T, a *Adapter) {
	// Initialize some policy in DB.
	initPolicy(t, a)
	// Note: you don't need to look at the above code
	// if you already have a working DB with policy inside.

	// Now the DB has policy, so we can provide a normal use case.
	// Create an adapter and an enforcer.
	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})
}
func testAutoSave(t *testing.T, a *Adapter) {

	// NewEnforcer() will load the policy automatically.
	e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)
	// AutoSave is enabled by default.
	// Now we disable it.
	e.EnableAutoSave(false)

	// Because AutoSave is disabled, the policy change only affects the policy in Casbin enforcer,
	// it doesn't affect the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	e.LoadPolicy()
	// This is still the original policy.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Now we enable the AutoSave.
	e.EnableAutoSave(true)

	// Because AutoSave is enabled, the policy change not only affects the policy in Casbin enforcer,
	// but also affects the policy in the storage.
	e.AddPolicy("alice", "data1", "write")
	// Reload the policy from the storage to see the effect.
	e.LoadPolicy()
	// The policy has a new rule: {"alice", "data1", "write"}.
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}, {"alice", "data1", "write"}})

	// Remove the added rule.
	e.RemovePolicy("alice", "data1", "write")
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}, {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"}})

	// Remove "data2_admin" related policy rules via a filter.
	// Two rules: {"data2_admin", "data2", "read"}, {"data2_admin", "data2", "write"} are deleted.
	e.RemoveFilteredPolicy(0, "data2_admin")
	e.LoadPolicy()
	testGetPolicy(t, e, [][]string{{"alice", "data1", "read"}, {"bob", "data2", "write"}})
}

func TestNilField(t *testing.T) {
	a, err := NewAdapter(&Config{})
	require.Nil(t, err)
	defer a.Close()

	e, err := casbin.NewEnforcer("examples/rbac_model.conf", a)
	require.Nil(t, err)
	e.EnableAutoSave(false)

	ok, err := e.AddPolicy("", "data1", "write")
	require.Nil(t, err)
	e.SavePolicy()
	assert.Nil(t, e.LoadPolicy())

	ok, err = e.Enforce("", "data1", "write")
	require.Nil(t, err)
	require.Equal(t, ok, true)
}

func TestAdapter(t *testing.T) {
	a, err := NewAdapter(&Config{})
	require.Nil(t, err)
	defer a.Close()
	testSaveLoad(t, a)
	testAutoSave(t, a)
}

func TestAdapterWithRecreateOnSave(t *testing.T) {
	a, err := NewAdapter(&Config{RecreateOnSave: true})
	require.Nil(t, err)
	defer a.Close()
	testSaveLoad(t, a)
	testAutoSave(t, a)
}

func TestAdapterWithTLS(t *testing.T) {
	certDir := "tests/nats/cfssl/certs/"
	a, err := NewAdapter(&Config{
		URL: "nats://localhost:4223",
		TLSConfig: TLSConfig{
			Enable:  true,
			Refresh: 1 * time.Second,
			File: TLSClientFiles{
				Cert:    certDir + "nats-client.pem",
				Key:     certDir + "nats-client-key.pem",
				RootCAs: certDir + "ca.pem",
			},
		},
	})
	require.Nil(t, err)
	defer a.Close()
	testSaveLoad(t, a)
	testAutoSave(t, a)
}
