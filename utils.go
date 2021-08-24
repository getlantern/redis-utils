package redisutils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/getlantern/errors"
	"github.com/reflog/minisentinel"
	"github.com/stretchr/testify/require"

	"github.com/getlantern/golog"
	"github.com/getlantern/keyman"
	"github.com/go-redis/redis/v8"
)

var log = golog.LoggerFor("redis-utils")

// Defaults used when required options are not provided.
const DefaultMasterName = "mymaster"
const DefaultSentinelPort = 36379
const DefaultPort = 6379

func parseRedisURL(redisURL string) (isSentinel bool, isTLS bool, password string, hosts []string, err error) {
	uri, err := url.ParseRequestURI(redisURL)
	if err != nil {
		return false, false, "", nil, errors.New("Invalid redis url %s: %v", redisURL, err)
	}
	if uri.Scheme != "redis" && uri.Scheme != "rediss" && uri.Scheme != "rediss+sentinel" {
		return false, false, "", nil, errors.New("%s should contain either a 'redi[s]://' or 'rediss+sentinel://' scheme", redisURL)
	}
	if uri.User != nil {
		password, _ = uri.User.Password()
	}
	hosts = strings.Split(uri.Host, ",")
	if hosts == nil {
		return false, false, "", nil, errors.New("%s does not contain a list of hosts", redisURL)
	}
	isSentinel = uri.Scheme == "rediss+sentinel"
	isTLS = isSentinel || uri.Scheme == "rediss"
	return isSentinel, isTLS, password, hosts, nil
}

type Config struct {
	CAFile         string // optional, if not set, will use host CA
	ClientKeyFile  string
	ClientCertFile string
	URL            string
	Timeout        time.Duration
	PoolSize       int
	MasterName     string
}

func SetupRedisClient(config *Config) (*redis.Client, error) {
	redisIsSentinel, redisUsesTLS, redisPassword, redisHosts, err := parseRedisURL(config.URL)
	if err != nil {
		return nil, errors.New("Failed to parse Redis URL: %v", err)
	}
	var redisDialer func(ctx context.Context, network, addr string) (net.Conn, error)
	if redisUsesTLS {
		if config.ClientKeyFile == "" {
			return nil, errors.New("Please set a client private key file")
		}
		if _, err := os.Stat(config.ClientKeyFile); os.IsNotExist(err) {
			return nil, errors.New("Cannot find client private key file")
		}
		if config.ClientCertFile == "" {
			return nil, errors.New("Please set a client certificate file")
		}
		if _, err := os.Stat(config.ClientCertFile); os.IsNotExist(err) {
			return nil, errors.New("Cannot find client certificate file")
		}
		redisClientCert, err := tls.LoadX509KeyPair(config.ClientCertFile, config.ClientKeyFile)
		if err != nil {
			return nil, errors.New("Failed to load client certificate: %v", err)
		}

		var certPool *x509.CertPool
		if config.CAFile != "" {
			if _, err2 := os.Stat(config.CAFile); os.IsNotExist(err2) {
				return nil, errors.New("Cannot find certificate authority file")
			}

			redisCACert, err2 := keyman.LoadCertificateFromFile(config.CAFile)
			if err2 != nil {
				return nil, errors.New("Failed to load CA cert: %v", err2)
			}
			certPool = redisCACert.PoolContainingCert()
		}

		// We use TLS as the transport. If we simply specify the TLSConfig, the Redis library will
		// establish TLS connections to Sentinel, but plain TCP connections to masters.
		redisDialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tls.Dial(network, addr, &tls.Config{
				InsecureSkipVerify: flag.Lookup("test.v") != nil, // during test runs, skip verification
				RootCAs:            certPool,
				Certificates:       []tls.Certificate{redisClientCert},
				ClientSessionCache: tls.NewLRUClientSessionCache(100),
			})
		}
	}
	opTimeout := config.Timeout - 500*time.Millisecond
	var c *redis.Client
	if redisIsSentinel {
		log.Debug("Using sentinel mode")
		for i, addr := range redisHosts {
			if !strings.Contains(addr, ":") {
				redisHosts[i] = addr + ":" + strconv.Itoa(DefaultSentinelPort)
			}
		}

		if config.MasterName == "" {
			config.MasterName = DefaultMasterName
		}

		c = redis.NewFailoverClient(&redis.FailoverOptions{
			SentinelAddrs:    redisHosts,
			SentinelPassword: redisPassword,
			Password:         redisPassword,
			PoolSize:         config.PoolSize,
			PoolTimeout:      opTimeout,
			ReadTimeout:      opTimeout,
			WriteTimeout:     opTimeout,
			IdleTimeout:      opTimeout,
			DialTimeout:      opTimeout,
			MasterName:       config.MasterName,
			Dialer:           redisDialer,
		})
	} else {
		host := redisHosts[0]
		if !strings.Contains(host, ":") {
			host = host + ":" + strconv.Itoa(DefaultPort)
		}
		c = redis.NewClient(&redis.Options{
			Password:     redisPassword,
			Addr:         host,
			PoolSize:     config.PoolSize,
			PoolTimeout:  opTimeout,
			ReadTimeout:  opTimeout,
			WriteTimeout: opTimeout,
			IdleTimeout:  opTimeout,
			DialTimeout:  opTimeout,
			Dialer:       redisDialer,
		})
	}

	if err := c.Ping(context.Background()).Err(); err != nil {
		return nil, errors.New("error pinging redis: %v", err)
	}
	return c, nil
}

func StartTestRedisSentinel(t *testing.T, masterName string) string {
	t.Helper()

	m := miniredis.NewMiniRedis()
	require.NoError(t, m.Start())
	s := minisentinel.NewSentinel(m, minisentinel.WithMasterName(masterName))
	require.NoError(t, s.Start())
	return s.Addr()
}

func StartTestRedis(t *testing.T) string {
	t.Helper()

	m := miniredis.NewMiniRedis()
	require.NoError(t, m.Start())
	return m.Addr()
}
