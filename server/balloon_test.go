package server

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func serveUnixSocket(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()

	socketPath := filepath.Join(t.TempDir(), "firecracker.sock")
	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	server := &http.Server{Handler: handler}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })

	return socketPath
}

func TestCreateBalloonHandler(t *testing.T) {
	var method, path string
	var body map[string]interface{}
	socketPath := serveUnixSocket(t, func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		data, _ := io.ReadAll(r.Body)
		json.Unmarshal(data, &body)
		w.WriteHeader(http.StatusNoContent)
	})

	handler := newCreateBalloonHandler(socketPath, &FirecrackerBalloonConfig{
		AmountMib: 0, DeflateOnOom: true, StatsPollingIntervalS: 5, FreePageReporting: true,
	})
	require.NoError(t, handler.Fn(context.Background(), nil))

	assert.Equal(t, createBalloonHandlerName, handler.Name)
	assert.Equal(t, http.MethodPut, method)
	assert.Equal(t, "/balloon", path)
	assert.Equal(t, map[string]interface{}{
		"amount_mib":               float64(0),
		"deflate_on_oom":           true,
		"stats_polling_interval_s": float64(5),
		"free_page_reporting":      true,
	}, body)
}

func TestCreateBalloonHandlerOmitsDisabledFeatures(t *testing.T) {
	var body map[string]interface{}
	socketPath := serveUnixSocket(t, func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		json.Unmarshal(data, &body)
		w.WriteHeader(http.StatusNoContent)
	})

	handler := newCreateBalloonHandler(socketPath, &FirecrackerBalloonConfig{AmountMib: 128})
	require.NoError(t, handler.Fn(context.Background(), nil))

	assert.Equal(t, map[string]interface{}{"amount_mib": float64(128), "deflate_on_oom": false}, body)
}

func TestCreateBalloonHandlerError(t *testing.T) {
	socketPath := serveUnixSocket(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"fault_message":"Amount of pages requested is too large."}`))
	})

	handler := newCreateBalloonHandler(socketPath, &FirecrackerBalloonConfig{AmountMib: 1 << 20})
	err := handler.Fn(context.Background(), nil)
	assert.ErrorContains(t, err, "400 Bad Request")
	assert.ErrorContains(t, err, "Amount of pages requested is too large.")
}
