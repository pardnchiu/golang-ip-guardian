package golangIPGuardian

import (
	"context"
	"fmt"
	"net/http"

	"github.com/redis/go-redis/v9"
)

func New(c *Config) (*IPGuardian, error) {
	if c.Redis.Host == "" {
		c.Redis.Host = "localhost"
	}

	if c.Redis.Port <= 0 || c.Redis.Port > 65535 {
		c.Redis.Port = 6379
	}

	logger, err := newLogger(c.Log)
	if err != nil {
		return nil, logger.error("Failed to init logger", err.Error())
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", c.Redis.Host, c.Redis.Port),
		Password: c.Redis.Password,
		DB:       c.Redis.DB,
	})
	if _, err := redisClient.Ping(context.Background()).Result(); err != nil {
		return nil, logger.error("Failed to connect Redis", err.Error())
	}

	// var abuseIPDBApi *AbuseIPDBApi
	// if c.AbuseIPDBToken != "" {
	// 	abuseIPDBApi = &AbuseIPDBApi{
	// 		Context: context.Background(),
	// 		IsPaid:  c.AbuseIPDBIsPaid,
	// 		Redis:   redisClient,
	// 		HTTP:    &http.Client{Timeout: 10 * time.Second},
	// 		Token:   c.AbuseIPDBToken,
	// 		Logger:  logger,
	// 	}
	// }

	instance := &IPGuardian{
		Context: context.Background(),
		Config:  c,
		Redis:   redisClient,
		Logger:  logger,
		// AbuseIPDBApi: abuseIPDBApi,
	}

	instance.Manager = &Manager{
		Trust: instance.newTrustManager(),
		Ban:   instance.newBanManager(),
		Block: instance.newBlockManager(),
	}

	instance.GeoLite2 = instance.newGeoLite2()

	return instance, nil
}

func (i *IPGuardian) Close() error {
	if i.Redis != nil {
		if err := i.Redis.Close(); err != nil {
			return err
		}
	}
	if i.GeoLite2 != nil {
		i.GeoLite2.close()
	}

	i.Logger.close()

	return nil
}

type IPGuardianResult struct {
	Success    bool   `json:"success"`
	StatusCode int    `json:"status_code"`
	Error      string `json:"error"`
}

func (i *IPGuardian) Check(r *http.Request, w http.ResponseWriter) IPGuardianResult {
	device, err := i.getDevice(w, r)
	if err != nil {
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusInternalServerError,
			Error:      "Failed to get device info",
		}
	}

	if device.Is.Trust {
		// * this device is trusted, skip further checks
		return IPGuardianResult{
			Success:    true,
			StatusCode: http.StatusOK,
		}
	}

	if device.Is.Ban {
		// * this device is banned, return error
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusForbidden,
			Error:      "Device is banned, IP: " + device.IP.Address,
		}
	}

	// * auto add to ban list if device is blocked and continue request

	if i.Config.Parameter.BlockToBan <= 0 {
		i.Config.Parameter.BlockToBan = 8
	}

	if i.Config.Parameter.RateLimitNormal <= 0 {
		i.Config.Parameter.RateLimitNormal = 100
	}
	if i.Config.Parameter.RateLimitSuspicious <= 0 {
		i.Config.Parameter.RateLimitSuspicious = 50
	}
	if i.Config.Parameter.RateLimitDangerous <= 0 {
		i.Config.Parameter.RateLimitDangerous = 20
	}

	if device.Is.Block && device.IP.BlockCount >= i.Config.Parameter.BlockToBan {
		i.Manager.Ban.Add(device.IP.Address, "Device is blocked and continue to request, IP: "+device.IP.Address)
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusForbidden,
			Error:      "Device is banned, IP: " + device.IP.Address,
		}
	}

	score, err := i.dynamicScore(device)
	if err != nil {
		// TODO: 後續要改寫，不能直接通過
		i.Logger.error("Failed to detect suspicious activity", err.Error())
	}

	if score.IsBlock {
		// * dynamicScore 已自動添加至 blocklist，不需重複添加
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusForbidden,
			Error:      "Device is blocked, IP: " + device.IP.Address,
		}
	}

	if score.IsDangerous && device.IP.RequestCount >= i.Config.Parameter.RateLimitDangerous {
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusForbidden,
			Error:      "Device is reached rate limit (Dangerous), IP: " + device.IP.Address,
		}
	}
	if score.IsSuspicious && device.IP.RequestCount >= i.Config.Parameter.RateLimitSuspicious {
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusForbidden,
			Error:      "Device is reached rate limit (Suspicious), IP: " + device.IP.Address,
		}
	}
	if device.IP.RequestCount >= i.Config.Parameter.RateLimitNormal {
		return IPGuardianResult{
			Success:    false,
			StatusCode: http.StatusForbidden,
			Error:      "Device is reached rate limit (Normal), IP: " + device.IP.Address,
		}
	}

	// TODO: AbuseIPDB 檢查未完成

	return IPGuardianResult{
		Success:    true,
		StatusCode: http.StatusOK,
	}
}
