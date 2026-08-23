// Copyright (C) MongoDB, Inc. 2017-present.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License. You may obtain
// a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

package auth

// modified by unixman: removed scram, depends on golang.org / x / text

import (
//	"fmt"

	"context"
	"net/http"

	"github.com/unix-world/smartgo/db/mongo-driver/x/mongo/driver"
)

// DefaultAuthenticator uses MONGODB-CR
// on the server version.
type DefaultAuthenticator struct {
	Cred *Cred

	// The authenticator to use for speculative authentication. Because the correct auth mechanism is unknown when doing
	// the initial hello, MONGODB-CR is used for the speculative attempt.
	speculativeAuthenticator SpeculativeAuthenticator

	httpClient *http.Client
}

var _ SpeculativeAuthenticator = (*DefaultAuthenticator)(nil)

// CreateSpeculativeConversation creates a speculative conversation for authentication.
func (a *DefaultAuthenticator) CreateSpeculativeConversation() (SpeculativeConversation, error) {
	return a.speculativeAuthenticator.CreateSpeculativeConversation()
}

// Auth authenticates the connection.
func (a *DefaultAuthenticator) Auth(ctx context.Context, cfg *Config) error {
	var actual Authenticator
	var err error

	// unixman: removed scram
	actual, err = newMongoDBCRAuthenticator(a.Cred, a.httpClient)

	if err != nil {
		return newAuthError("error creating authenticator", err)
	}

	return actual.Auth(ctx, cfg)
}

// Reauth reauthenticates the connection.
func (a *DefaultAuthenticator) Reauth(_ context.Context, _ *driver.AuthConfig) error {
	return newAuthError("DefaultAuthenticator does not support reauthentication", nil)
}

