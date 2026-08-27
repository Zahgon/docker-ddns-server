package handler

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"os"
	"strconv"
	"strings"
	"time"

	"github.com/benjaminbear/docker-ddns-server/dyndns/model"
	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/tg123/go-htpasswd"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

type Handler struct {
	DB               *gorm.DB
	AuthAdmin        bool
	Config           Envs
	Title            string
	DisableAdminAuth bool
	LastClearedLogs  time.Time
	ClearInterval    uint64
	AllowWildcard    bool
	LogoutUrl        string
}

type Envs struct {
	AdminLogin string
	Domains    []string
}

type CustomValidator struct {
	Validator *validator.Validate
}

// Validate implements the Validator.
func (cv *CustomValidator) Validate(i interface{}) error {
	return cv.Validator.Struct(i)
}

// defaultValidator replaces echo's e.Validator, which gin has no equivalent for.
var defaultValidator = &CustomValidator{Validator: validator.New()}

// Validate validates a struct against its "validate" tags, like echo's c.Validate did.
func (h *Handler) Validate(i interface{}) error {
	return defaultValidator.Validate(i)
}

type Error struct {
	Message string `json:"message"`
}

// basicAuth replicates echo's middleware.BasicAuth: it parses the Authorization
// header, calls authFunc and answers with a 401 challenge whenever it fails.
func basicAuth(authFunc func(username, password string, c *gin.Context) (bool, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		username, password, ok := parseBasicAuth(c.GetHeader("Authorization"))
		if !ok {
			basicAuthChallenge(c)
			return
		}

		valid, err := authFunc(username, password, c)
		if err != nil || !valid {
			basicAuthChallenge(c)
			return
		}

		c.Next()
	}
}

func parseBasicAuth(header string) (username, password string, ok bool) {
	const prefix = "Basic "
	if len(header) < len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", "", false
	}

	raw, err := base64.StdEncoding.DecodeString(header[len(prefix):])
	if err != nil {
		return "", "", false
	}

	credentials := strings.SplitN(string(raw), ":", 2)
	if len(credentials) != 2 {
		return "", "", false
	}

	return credentials[0], credentials[1], true
}

func basicAuthChallenge(c *gin.Context) {
	c.Header("WWW-Authenticate", `Basic realm="Restricted"`)
	c.AbortWithStatus(http.StatusUnauthorized)
}

// BasicAuthAdmin is the gin middleware guarding the admin routes.
func (h *Handler) BasicAuthAdmin() gin.HandlerFunc {
	return basicAuth(h.AuthenticateAdmin)
}

// BasicAuthUpdate is the gin middleware guarding the dyndns update routes.
func (h *Handler) BasicAuthUpdate() gin.HandlerFunc {
	return basicAuth(h.AuthenticateUpdate)
}

// Authenticate is the method the website admin user and the host update user have to authenticate against.
// To gather admin rights the username password combination must match with the credentials given by the env var.
func (h *Handler) AuthenticateUpdate(username, password string, c *gin.Context) (bool, error) {
	h.CheckClearInterval()
	reqParameter := c.Query("hostname")
	reqArr := strings.SplitN(reqParameter, ".", 2)
	if len(reqArr) != 2 {
		log.Println("Error: Something wrong with the hostname parameter")
		return false, nil
	}

	host := &model.Host{}
	if err := h.DB.Where(&model.Host{UserName: username, Password: password, Hostname: reqArr[0], Domain: reqArr[1]}).First(host).Error; err != nil {
		log.Println("Error: ", err)
		return false, nil
	}
	if host.ID == 0 {
		log.Println("hostname or user user credentials unknown")
		return false, nil
	}
	c.Set("updateHost", host)

	return true, nil
}
func (h *Handler) AuthenticateAdmin(username, password string, c *gin.Context) (bool, error) {
	h.AuthAdmin = false
	ok, err := h.authByEnv(username, password)
	if err != nil {
		log.Println("Error:", err)
		return false, nil
	}

	if ok {
		h.AuthAdmin = true
		return true, nil
	}

	return false, nil
}
func (h *Handler) authByEnv(username, password string) (bool, error) {
	hashReader := strings.NewReader(h.Config.AdminLogin)

	pw, err := htpasswd.NewFromReader(hashReader, htpasswd.DefaultSystems, nil)
	if err != nil {
		return false, err
	}

	if ok := pw.Match(username, password); ok {
		return true, nil
	}

	return false, nil
}

// ParseEnvs parses all needed environment variables:
// DDNS_ADMIN_LOGIN: The basic auth login string in htpasswd style.
// DDNS_DOMAINS: All domains that will be handled by the dyndns server.
func (h *Handler) ParseEnvs() (adminAuth bool, err error) {
	log.Println("Read environment variables")
	h.Config = Envs{}
	adminAuth = true
	h.Config.AdminLogin = os.Getenv("DDNS_ADMIN_LOGIN")
	if h.Config.AdminLogin == "" {
		log.Println("No Auth! DDNS_ADMIN_LOGIN should be set")
		adminAuth = false
		h.AuthAdmin = true
		h.DisableAdminAuth = true
	}
	var ok bool
	h.Title, ok = os.LookupEnv("DDNS_TITLE")
	if !ok {
		h.Title = "TheBBCloud DynDNS"
	}
	allowWildcard, ok := os.LookupEnv("DDNS_ALLOW_WILDCARD")
	if ok {
		h.AllowWildcard, err = strconv.ParseBool(allowWildcard)
		if err == nil {
			log.Println("Wildcard allowed")
		}
	}
	logoutUrl, ok := os.LookupEnv("DDNS_LOGOUT_URL")
	if ok {
		if len(logoutUrl) > 0 {
			log.Println("Logout url set: ", logoutUrl)
			h.LogoutUrl = logoutUrl
		}
	}

	clearEnv := os.Getenv("DDNS_CLEAR_LOG_INTERVAL")
	clearInterval, err := strconv.ParseUint(clearEnv, 10, 32)
	if err != nil {
		log.Println("No log clear interval found")
	} else {
		log.Println("log clear interval found: ", clearInterval, "days")
		h.ClearInterval = clearInterval
		if clearInterval > 0 {
			h.LastClearedLogs = time.Now()
		}
	}

	h.Config.Domains = strings.Split(os.Getenv("DDNS_DOMAINS"), ",")
	if len(h.Config.Domains) < 1 {
		return adminAuth, fmt.Errorf("environment variable DDNS_DOMAINS has to be set")
	}

	return adminAuth, nil
}

// InitDB creates an empty database and creates all tables if there isn't already one, or opens the existing one.
func (h *Handler) InitDB() (err error) {
	if _, err := os.Stat("database"); os.IsNotExist(err) {
		err = os.MkdirAll("database", os.ModePerm)
		if err != nil {
			return err
		}
	}

	h.DB, err = gorm.Open(sqlite.Open("database/ddns.db"), &gorm.Config{})
	if err != nil {
		return err
	}

	err = h.DB.AutoMigrate(&model.Host{}, &model.CName{}, &model.Log{})

	return err
}

// Check if a log cleaning is needed
func (h *Handler) CheckClearInterval() {
	if !h.LastClearedLogs.IsZero() {
		if !DateEqual(time.Now(), h.LastClearedLogs) {
			go h.ClearLogs()
		}
	}
}

// compare two dates
func DateEqual(date1, date2 time.Time) bool {
	y1, m1, d1 := date1.Date()
	y2, m2, d2 := date2.Date()
	return y1 == y2 && m1 == m2 && d1 == d2
}
