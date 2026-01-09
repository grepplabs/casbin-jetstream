Casbin JetStream
====

[![Build](https://github.com/grepplabs/casbin-jetstream/actions/workflows/ci.yml/badge.svg)](https://github.com/grepplabs/casbin-jetstream/actions/workflows/ci.yml)
[![Godoc](https://godoc.org/github.com/casbin/casbin?status.svg)](https://pkg.go.dev/github.com/grepplabs/casbin-jetstream)
[![Release](https://img.shields.io/github/v/release/grepplabs/casbin-jetstream?sort=semver)](https://github.com/grepplabs/casbin-jetstream/releases)

Casbin JetStream is the [NATS JetStream](https://docs.nats.io/nats-concepts/jetstream) adapter for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load policy from JetStream or save policy to it.

## Installation

    go get github.com/grepplabs/casbin-jetstream

## Usage Examples

### Basic Usage

```go
package main

import (
 "github.com/casbin/v3"
 jsadapter "github.com/grepplabs/casbin-jetstream"
)

func main() {
 // Initialize a casbin jetstream adapter and use it in a Casbin enforcer:
 a, _ := jsadapter.NewAdapter(&jsadapter.Config{
  URL: "nats://localhost:4222",
 })
 e, _ := casbin.NewEnforcer("examples/rbac_model.conf", a)

 // Load the policy from KV Store.
 e.LoadPolicy()

 // Check the permission.
 e.Enforce("alice", "data1", "read")

 // Modify the policy.
 // e.AddPolicy(...)
 // e.RemovePolicy(...)

 // Save the policy back to KV Store.
 e.SavePolicy()
}
```

### With mTLS

```go

 a, _ := jsadapter.NewAdapter(&jsadapter.Config{
  URL:    "nats://localhost:4223",
  Bucket: "casbin_rules",
  TLSConfig: jsadapter.TLSConfig{
   Enable:  true,
   Refresh: 15 * time.Second,
   File: jsadapter.TLSClientFiles{
    Cert:    "/etc/nats/certs/nats-client.pem",
    Key:     "/etc/nats/certs/nats-client-key.pem",
    RootCAs: "/etc/nats/certs/ca.pem",
   },
  },
 })
 defer a.Close()
```
