package redisutils

import (
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/reflog/minisentinel"
	"github.com/stretchr/testify/require"
)

func TestParseRedisURL(t *testing.T) {
	for _, testCase := range []struct {
		input            string
		expectedPassword string
		expectedHosts    []string
		sentinel         bool
		tls              bool
	}{
		{"rediss+sentinel://:@1.2.3.4", "", []string{"1.2.3.4"}, true, true},
		{"rediss+sentinel://:pass123@1.2.3.4", "pass123", []string{"1.2.3.4"}, true, true},
		{"rediss+sentinel://bob:pass123@1.2.3.4", "pass123", []string{"1.2.3.4"}, true, true},
		{"rediss+sentinel://:@1.2.3.4,5.6.7.8", "", []string{"1.2.3.4", "5.6.7.8"}, true, true},
		{"rediss+sentinel://:pass123@1.2.3.4,5.6.7.8", "pass123", []string{"1.2.3.4", "5.6.7.8"}, true, true},
		{"rediss+sentinel://bob:pass123@1.2.3.4,5.6.7.8", "pass123", []string{"1.2.3.4", "5.6.7.8"}, true, true},
		{"rediss+sentinel://:@1.2.3.4:26379", "", []string{"1.2.3.4:26379"}, true, true},
		{"rediss+sentinel://:pass123@1.2.3.4:26379", "pass123", []string{"1.2.3.4:26379"}, true, true},
		{"rediss+sentinel://bob:pass123@1.2.3.4:26379", "pass123", []string{"1.2.3.4:26379"}, true, true},
		{"rediss+sentinel://:@1.2.3.4:26379,5.6.7.8:26379", "", []string{"1.2.3.4:26379", "5.6.7.8:26379"}, true, true},
		{"rediss+sentinel://:pass123@1.2.3.4:26379,5.6.7.8:26379", "pass123", []string{"1.2.3.4:26379", "5.6.7.8:26379"}, true, true},
		{"rediss+sentinel://bob:pass123@1.2.3.4:26379,5.6.7.8:26379", "pass123", []string{"1.2.3.4:26379", "5.6.7.8:26379"}, true, true},
		{"redis://:@1.2.3.4", "", []string{"1.2.3.4"}, false, false},
		{"rediss://:@1.2.3.4", "", []string{"1.2.3.4"}, false, true},
		{"redis://:pass123@1.2.3.4:26379", "pass123", []string{"1.2.3.4:26379"}, false, false},
		{"redis://bob:pass123@1.2.3.4:26379", "pass123", []string{"1.2.3.4:26379"}, false, false},
		{"redis://:pass123@somedomain.com", "pass123", []string{"somedomain.com"}, false, false},
	} {
		t.Run(testCase.input, func(t *testing.T) {
			isSentinel, isTLS, password, hosts, err := parseRedisURL(testCase.input)
			require.NoError(t, err)
			require.Equal(t, testCase.sentinel, isSentinel)
			require.Equal(t, testCase.tls, isTLS)
			require.Equal(t, testCase.expectedPassword, password)
			require.Equal(t, testCase.expectedHosts, hosts)
		})
	}
}

func newString(s string) *string {
	return &s
}

func testServerTLS(t *testing.T) *tls.Config {
	t.Helper()

	cert, err := tls.LoadX509KeyPair("test_data/server.crt", "test_data/server.key")
	require.NoError(t, err)

	cp := x509.NewCertPool()
	rootca, err := ioutil.ReadFile("test_data/client.crt")
	require.NoError(t, err)
	require.True(t, cp.AppendCertsFromPEM(rootca), "client cert err")
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ServerName:   "Server",
		ClientCAs:    cp,
	}
}

func TestRegularConnect(t *testing.T) {
	m := miniredis.NewMiniRedis()
	require.NoError(t, m.Start())
	defer m.Close()
	r, err := SetupRedisClient(&Config{
		URL:      "redis://:@" + m.Addr(),
		Timeout:  1 * time.Second,
		PoolSize: 1,
	})
	require.NoError(t, err)
	require.NotNil(t, r)
}
func TestTLSConnect(t *testing.T) {
	m := miniredis.NewMiniRedis()
	require.NoError(t, m.StartTLS(testServerTLS(t)))
	defer m.Close()
	r, err := SetupRedisClient(&Config{
		CAFile:         "test_data/client.crt",
		ClientKeyFile:  "test_data/client.key",
		ClientCertFile: "test_data/client.crt",
		URL:            "rediss://:@" + m.Addr(),
		Timeout:        1 * time.Second,
		PoolSize:       1,
	})
	require.NoError(t, err)
	require.NotNil(t, r)
}

func TestSentinelConnect(t *testing.T) {
	m := miniredis.NewMiniRedis()
	require.NoError(t, m.StartTLS(testServerTLS(t)))
	defer m.Close()

	s := minisentinel.NewSentinel(m, minisentinel.WithReplica(m), minisentinel.WithMasterName("master"))
	require.NoError(t, s.StartTLS(testServerTLS(t)))
	defer s.Close()
	r, err := SetupRedisClient(&Config{
		CAFile:         "test_data/client.crt",
		ClientKeyFile:  "test_data/client.key",
		ClientCertFile: "test_data/client.crt",
		URL:            "rediss+sentinel://:@" + s.Addr(),
		Timeout:        1 * time.Second,
		PoolSize:       1,
		MasterName:     "master",
	})

	require.NoError(t, err)
	require.NotNil(t, r)
}
