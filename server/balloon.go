package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/firecracker-microvm/firecracker-go-sdk"
)

const createBalloonHandlerName = "fireactions.CreateBalloon"

// balloonRequest is the body of Firecracker's PUT /balloon. The SDK's balloon
// model predates free page reporting, so the request is sent directly to the
// API socket instead.
type balloonRequest struct {
	AmountMib             int64 `json:"amount_mib"`
	DeflateOnOom          bool  `json:"deflate_on_oom"`
	StatsPollingIntervalS int64 `json:"stats_polling_interval_s,omitempty"`
	FreePageReporting     bool  `json:"free_page_reporting,omitempty"`
}

func (c *FirecrackerBalloonConfig) toRequest() balloonRequest {
	return balloonRequest{
		AmountMib:             c.AmountMib,
		DeflateOnOom:          c.DeflateOnOom,
		StatsPollingIntervalS: c.StatsPollingIntervalS,
		FreePageReporting:     c.FreePageReporting,
	}
}

// newCreateBalloonHandler returns a handler that attaches a balloon device to
// the MicroVM. It must run before the instance starts.
func newCreateBalloonHandler(socketPath string, config *FirecrackerBalloonConfig) firecracker.Handler {
	return firecracker.Handler{
		Name: createBalloonHandlerName,
		Fn: func(ctx context.Context, _ *firecracker.Machine) error {
			return putBalloon(ctx, socketPath, config.toRequest())
		},
	}
}

func putBalloon(ctx context.Context, socketPath string, balloon balloonRequest) error {
	body, err := json.Marshal(balloon)
	if err != nil {
		return fmt.Errorf("encoding balloon: %w", err)
	}

	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
		},
	}}
	defer client.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, "http://localhost/balloon", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating balloon request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("creating balloon: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("creating balloon: %s: %s", resp.Status, bytes.TrimSpace(msg))
	}

	return nil
}
