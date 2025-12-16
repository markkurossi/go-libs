//
// project.go
//
// Copyright (c) 2019-2025 Markku Rossi
//
// All rights reserved.
//

// Package fn provides help functions for Google Cloud Function
// implementations.
package fn

import (
	"context"

	"golang.org/x/oauth2/google"
	"google.golang.org/api/compute/v1"
)

// GetProjectID returns the Google Cloud Functions project ID.
func GetProjectID() (string, error) {
	ctx := context.Background()

	credentials, err := google.FindDefaultCredentials(ctx, compute.ComputeScope)
	if err != nil {
		return "", err
	}

	return credentials.ProjectID, nil
}
