package versiondiff

import (
	"fmt"

	pb "github.com/cloudfieldcz/shieldoo-gate/internal/scanner/guarddog/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// dialBridge connects to the scanner-bridge gRPC server over a Unix socket.
// Returns the client, a closer function, and any error. Mirrors the helper in
// internal/scanner/ai/client.go — duplicated rather than imported to avoid a
// cross-package dependency for a four-line wrapper.
func dialBridge(socketPath string) (pb.ScannerBridgeClient, func() error, error) {
	conn, err := grpc.NewClient(
		"unix://"+socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("version-diff scanner: dialing bridge at %s: %w", socketPath, err)
	}
	return pb.NewScannerBridgeClient(conn), conn.Close, nil
}
