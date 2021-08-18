package redisutils

import (
	"context"
	"crypto/tls"
	"flag"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/getlantern/errors"

	"github.com/getlantern/golog"
	"github.com/getlantern/keyman"
	"github.com/go-redis/redis/v8"
)

var log = golog.LoggerFor("redis-utils")
var redisURLRegExp = regexp.MustCompile(`^rediss?(\+sentinel)?://.*?:(.*?)@([\d\.(:\d*)?,]+)$`)

// Defaults used when required options are not provided.
const DefaultMasterName = "mymaster"
const DefaultSentinelPort = 36379

func parseRedisURL(redisURL string) (isSentinel bool, password string, hosts []string, err error) {
	matches := redisURLRegExp.FindStringSubmatch(redisURL)
	if len(matches) < 4 {
		return false, "", nil, errors.New("%s should match %s", redisURL, redisURLRegExp.String())
	}
	hosts = strings.Split(matches[3], ",")
	if hosts == nil {
		return false, "", nil, errors.New("%s does not contain a list of hosts", redisURL)
	}
	if matches[1] != "" && matches[1] != "+sentinel" {
		return false, "", nil, errors.New("%s should contain either a 'redis://' or 'rediss+sentinel://' scheme", redisURL)
	}
	return matches[1] == "+sentinel", matches[2], hosts, nil
}

type Config struct {
	CAFile         string
	ClientKeyFile  string
	ClientCertFile string
	URL            string
	Timeout        time.Duration
	PoolSize       int
	MasterName     string
}

func SetupRedisClient(config *Config) (*redis.Client, error) {
	if config.CAFile == "" {
		return nil, errors.New("Please set a certificate authority file")
	}
	if _, err := os.Stat(config.CAFile); os.IsNotExist(err) {
		return nil, errors.New("Cannot find certificate authority file")
	}
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
	redisCACert, err := keyman.LoadCertificateFromFile(config.CAFile)
	if err != nil {
		return nil, errors.New("Failed to load CA cert: %v", err)
	}

	redisIsSentinel, redisPassword, redisHosts, err := parseRedisURL(config.URL)
	if err != nil {
		return nil, errors.New("Failed to parse Redis URL: %v", err)
	}

	// We use TLS as the transport. If we simply specify the TLSConfig, the Redis library will
	// establish TLS connections to Sentinel, but plain TCP connections to masters.
	redisDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		return tls.Dial(network, addr, &tls.Config{
			InsecureSkipVerify: flag.Lookup("test.v") != nil, // during test runs, skip verification
			RootCAs:            redisCACert.PoolContainingCert(),
			Certificates:       []tls.Certificate{redisClientCert},
			ClientSessionCache: tls.NewLRUClientSessionCache(100),
		})
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
		c = redis.NewClient(&redis.Options{
			Password:     redisPassword,
			Addr:         redisHosts[0],
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
