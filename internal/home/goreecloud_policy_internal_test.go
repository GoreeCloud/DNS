package home

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/stretchr/testify/require"
)

// Updates must not be enabled by inherited release channels or CLI flags.
func TestGoreeCloudUpdatePolicy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		disableFlag bool
		customURL   bool
	}{
		{name: "default"},
		{name: "legacy_custom_url", customURL: true},
		{name: "explicitly_disabled", disableFlag: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := &options{disableUpdate: tc.disableFlag}
			require.False(t, isUpdateEnabled(context.Background(), testLogger, opts, tc.customURL))
		})
	}
}

// A disabled update route must not dereference or invoke the old updater.
func TestGoreeCloudDisabledUpdateAPI(t *testing.T) {
	web := &webAPI{
		conf:   &webAPIConfig{disableUpdate: true},
		logger: testLogger,
	}

	req := httptest.NewRequest(http.MethodPost, "/control/update", nil)
	rec := httptest.NewRecorder()
	web.handleUpdate(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
}

// Version checks return a disabled response without reaching the network.
func TestGoreeCloudDisabledVersionCheck(t *testing.T) {
	web := &webAPI{
		conf:   &webAPIConfig{disableUpdate: true},
		logger: testLogger,
	}

	req := httptest.NewRequest(http.MethodPost, "/control/version.json", nil)
	rec := httptest.NewRecorder()
	web.handleVersionJSON(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Body.String(), `"disabled":true`)
}

// New installations must not persist full DNS query history by default.
func TestGoreeCloudInitialQueryLogPrivacy(t *testing.T) {
	require.False(t, config.QueryLog.Enabled)
	require.False(t, config.QueryLog.FileEnabled)
	require.Equal(t, timeutil.Duration(24*time.Hour), config.QueryLog.Interval)
}
