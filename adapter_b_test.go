package casbinjetstream

// Benchmarks based on https://github.com/casbin/casbin/blob/master/management_api_b_test.go

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/stretchr/testify/require"
)

func BenchmarkHasPolicySmall(b *testing.B) {
	adapter, err := NewAdapter(&Config{})
	require.Nil(b, err)
	defer adapter.Close()
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	require.Nil(b, err)

	// 100 roles, 10 resources.
	for i := 0; i < 100; i++ {
		_, _ = e.AddPolicy(fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.HasPolicy(fmt.Sprintf("user%d", rand.Intn(100)), fmt.Sprintf("data%d", rand.Intn(100)/10), "read")
	}
}

func BenchmarkHasPolicyMedium(b *testing.B) {
	adapter, err := NewAdapter(&Config{})
	require.Nil(b, err)
	defer adapter.Close()
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	require.Nil(b, err)

	// 1000 roles, 100 resources.
	pPolicies := make([][]string, 0)
	for i := 0; i < 1000; i++ {
		pPolicies = append(pPolicies, []string{fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read"})
	}
	_, err = e.AddPolicies(pPolicies)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.HasPolicy(fmt.Sprintf("user%d", rand.Intn(1000)), fmt.Sprintf("data%d", rand.Intn(1000)/10), "read")
	}
}

func BenchmarkHasPolicyLarge(b *testing.B) {
	adapter, err := NewAdapter(&Config{})
	require.Nil(b, err)
	defer adapter.Close()
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	require.Nil(b, err)

	// 10000 roles, 1000 resources.
	pPolicies := make([][]string, 0)
	for i := 0; i < 10000; i++ {
		pPolicies = append(pPolicies, []string{fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read"})
	}
	_, err = e.AddPolicies(pPolicies)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.HasPolicy(fmt.Sprintf("user%d", rand.Intn(10000)), fmt.Sprintf("data%d", rand.Intn(10000)/10), "read")
	}
}

func BenchmarkAddPolicySmall(b *testing.B) {
	adapter, err := NewAdapter(&Config{})
	require.Nil(b, err)
	defer adapter.Close()
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	require.Nil(b, err)

	// 100 roles, 10 resources.
	for i := 0; i < 100; i++ {
		_, _ = e.AddPolicy(fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.AddPolicy(fmt.Sprintf("user%d", rand.Intn(100)+100), fmt.Sprintf("data%d", (rand.Intn(100)+100)/10), "read")
	}
}

func BenchmarkAddPolicyMedium(b *testing.B) {
	adapter, err := NewAdapter(&Config{})
	require.Nil(b, err)
	defer adapter.Close()
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	require.Nil(b, err)

	// 1000 roles, 100 resources.
	pPolicies := make([][]string, 0)
	for i := 0; i < 1000; i++ {
		pPolicies = append(pPolicies, []string{fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read"})
	}
	_, err = e.AddPolicies(pPolicies)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.AddPolicy(fmt.Sprintf("user%d", rand.Intn(1000)+1000), fmt.Sprintf("data%d", (rand.Intn(1000)+1000)/10), "read")
	}
}

func BenchmarkAddPolicyLarge(b *testing.B) {
	adapter, err := NewAdapter(&Config{})
	require.Nil(b, err)
	defer adapter.Close()
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	require.Nil(b, err)

	// 10000 roles, 1000 resources.
	pPolicies := make([][]string, 0)
	for i := 0; i < 10000; i++ {
		pPolicies = append(pPolicies, []string{fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read"})
	}
	_, err = e.AddPolicies(pPolicies)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.AddPolicy(fmt.Sprintf("user%d", rand.Intn(10000)+10000), fmt.Sprintf("data%d", (rand.Intn(10000)+10000)/10), "read")
	}
}

func BenchmarkRemovePolicySmall(b *testing.B) {
	adapter, err := NewAdapter(&Config{})
	require.Nil(b, err)
	defer adapter.Close()
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	require.Nil(b, err)

	// 100 roles, 10 resources.
	for i := 0; i < 100; i++ {
		_, _ = e.AddPolicy(fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read")
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.RemovePolicy(fmt.Sprintf("user%d", rand.Intn(100)), fmt.Sprintf("data%d", rand.Intn(100)/10), "read")
	}
}

func BenchmarkRemovePolicyMedium(b *testing.B) {
	adapter, err := NewAdapter(&Config{})
	require.Nil(b, err)
	defer adapter.Close()
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	require.Nil(b, err)

	// 1000 roles, 100 resources.
	pPolicies := make([][]string, 0)
	for i := 0; i < 1000; i++ {
		pPolicies = append(pPolicies, []string{fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read"})
	}
	_, err = e.AddPolicies(pPolicies)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.RemovePolicy(fmt.Sprintf("user%d", rand.Intn(1000)), fmt.Sprintf("data%d", rand.Intn(1000)/10), "read")
	}
}

func BenchmarkRemovePolicyLarge(b *testing.B) {
	adapter, err := NewAdapter(&Config{})
	require.Nil(b, err)
	defer adapter.Close()
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", adapter)
	require.Nil(b, err)

	// 10000 roles, 1000 resources.
	pPolicies := make([][]string, 0)
	for i := 0; i < 10000; i++ {
		pPolicies = append(pPolicies, []string{fmt.Sprintf("user%d", i), fmt.Sprintf("data%d", i/10), "read"})
	}
	_, err = e.AddPolicies(pPolicies)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = e.RemovePolicy(fmt.Sprintf("user%d", rand.Intn(10000)), fmt.Sprintf("data%d", rand.Intn(10000)/10), "read")
	}
}
