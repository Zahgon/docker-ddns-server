package handler

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	l "log"

	"github.com/benjaminbear/docker-ddns-server/dyndns/nswrapper"

	"github.com/benjaminbear/docker-ddns-server/dyndns/model"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

const (
	UNAUTHORIZED = "You are not allowed to view that content"
)

// GetHost fetches a host from the database by "id".
func (h *Handler) GetHost(c *gin.Context) {
	if !h.AuthAdmin {
		c.JSON(http.StatusUnauthorized, &Error{UNAUTHORIZED})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	host := &model.Host{}
	if err = h.DB.First(host, id).Error; err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	// Display site
	c.JSON(http.StatusOK, id)
}

// ListHosts fetches all hosts from database and lists them on the website.
func (h *Handler) ListHosts(c *gin.Context) {
	if !h.AuthAdmin {
		c.JSON(http.StatusUnauthorized, &Error{UNAUTHORIZED})
		return
	}

	hosts := new([]model.Host)
	if err := h.DB.Find(hosts).Error; err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	c.HTML(http.StatusOK, "listhosts", gin.H{
		"hosts": hosts,
		"title": h.Title,
	})
}

// AddHost just renders the "add host" website.
func (h *Handler) AddHost(c *gin.Context) {
	if !h.AuthAdmin {
		c.JSON(http.StatusUnauthorized, &Error{UNAUTHORIZED})
		return
	}

	c.HTML(http.StatusOK, "edithost", gin.H{
		"addEdit": "add",
		"config":  h.Config,
		"title":   h.Title,
	})
}

// EditHost fetches a host by "id" and renders the "edit host" website.
func (h *Handler) EditHost(c *gin.Context) {
	if !h.AuthAdmin {
		c.JSON(http.StatusUnauthorized, &Error{UNAUTHORIZED})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	host := &model.Host{}
	if err = h.DB.First(host, id).Error; err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	c.HTML(http.StatusOK, "edithost", gin.H{
		"host":    host,
		"addEdit": "edit",
		"config":  h.Config,
		"title":   h.Title,
	})
}

// CreateHost validates the host data from the "add host" website,
// adds the host entry to the database,
// and adds the entry to the DNS server.
func (h *Handler) CreateHost(c *gin.Context) {
	if !h.AuthAdmin {
		c.JSON(http.StatusUnauthorized, &Error{UNAUTHORIZED})
		return
	}

	host := &model.Host{}
	if err := c.ShouldBind(host); err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	if err := h.Validate(host); err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	if err := h.checkUniqueHostname(host.Hostname, host.Domain); err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}
	host.LastUpdate = time.Now()
	if err := h.DB.Create(host).Error; err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	// If a ip is set create dns entry
	if host.Ip != "" {
		ipType := nswrapper.GetIPType(host.Ip)
		if ipType == "" {
			c.JSON(http.StatusBadRequest, &Error{fmt.Sprintf("ip %s is not a valid ip", host.Ip)})
			return
		}

		if err := nswrapper.UpdateRecord(host.Hostname, host.Ip, ipType, host.Domain, host.Ttl, h.AllowWildcard); err != nil {
			c.JSON(http.StatusBadRequest, &Error{err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, host)
}

// UpdateHost validates the host data from the "edit host" website,
// and compares the host data with the entry in the database by "id".
// If anything has changed the database and DNS entries for the host will be updated.
func (h *Handler) UpdateHost(c *gin.Context) {
	if !h.AuthAdmin {
		c.JSON(http.StatusUnauthorized, &Error{UNAUTHORIZED})
		return
	}

	hostUpdate := &model.Host{}
	if err := c.ShouldBind(hostUpdate); err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	host := &model.Host{}
	if err = h.DB.First(host, id).Error; err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	forceRecordUpdate := host.UpdateHost(hostUpdate)
	if err = h.Validate(host); err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	if err = h.DB.Save(host).Error; err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	// If ip or ttl changed update dns entry
	if forceRecordUpdate {
		ipType := nswrapper.GetIPType(host.Ip)
		if ipType == "" {
			c.JSON(http.StatusBadRequest, &Error{fmt.Sprintf("ip %s is not a valid ip", host.Ip)})
			return
		}

		if err = nswrapper.UpdateRecord(host.Hostname, host.Ip, ipType, host.Domain, host.Ttl, h.AllowWildcard); err != nil {
			c.JSON(http.StatusBadRequest, &Error{err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, host)
}

// DeleteHost fetches a host entry from the database by "id"
// and deletes the database and DNS server entry to it.
func (h *Handler) DeleteHost(c *gin.Context) {
	if !h.AuthAdmin {
		c.JSON(http.StatusUnauthorized, &Error{UNAUTHORIZED})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	host := &model.Host{}
	if err = h.DB.First(host, id).Error; err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	err = h.DB.Transaction(func(tx *gorm.DB) error {
		if err = tx.Unscoped().Delete(host).Error; err != nil {
			return err
		}

		if err = tx.Where(&model.Log{HostID: uint(id)}).Delete(&model.Log{}).Error; err != nil {
			return err
		}

		if err = tx.Where(&model.CName{TargetID: uint(id)}).Delete(&model.CName{}).Error; err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	if err = nswrapper.DeleteRecord(host.Hostname, host.Domain, h.AllowWildcard); err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	c.JSON(http.StatusOK, id)
}

// UpdateIP implements the update method called by the routers.
// Hostname, IP and senders IP are validated, a log entry is created
// and finally if everything is ok, the DNS Server will be updated
func (h *Handler) UpdateIP(c *gin.Context) {
	value, exists := c.Get("updateHost")
	host, ok := value.(*model.Host)
	if !exists || !ok {
		c.String(http.StatusBadRequest, "badauth\n")
		return
	}

	var err error
	log := &model.Log{Status: false, Host: *host, TimeStamp: time.Now(), UserAgent: nswrapper.ShrinkUserAgent(c.Request.UserAgent())}
	log.SentIP = c.Query("myip")

	// Get caller IP
	log.CallerIP, _ = nswrapper.GetCallerIP(c.Request)
	if log.CallerIP == "" {
		log.CallerIP, _, err = net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil {
			log.Message = "Bad Request: Unable to get caller IP"
			if err = h.CreateLogEntry(log); err != nil {
				l.Println(err)
			}

			c.String(http.StatusBadRequest, "badrequest\n")
			return
		}
	}

	// Validate hostname
	hostname := c.Query("hostname")
	if hostname == "" || hostname != host.Hostname+"."+host.Domain {
		log.Message = "Hostname or combination of authenticated user and hostname is invalid"
		if err = h.CreateLogEntry(log); err != nil {
			l.Println(err)
		}

		c.String(http.StatusBadRequest, "notfqdn\n")
		return
	}

	// Get IP type
	ipType := nswrapper.GetIPType(log.SentIP)
	if ipType == "" {
		log.SentIP = log.CallerIP
		ipType = nswrapper.GetIPType(log.SentIP)
		if ipType == "" {
			log.Message = "Bad Request: Sent IP is invalid"
			if err = h.CreateLogEntry(log); err != nil {
				l.Println(err)
			}

			c.String(http.StatusBadRequest, "badrequest\n")
			return
		}
	}

	// Add/update DNS record
	if err = nswrapper.UpdateRecord(log.Host.Hostname, log.SentIP, ipType, log.Host.Domain, log.Host.Ttl, h.AllowWildcard); err != nil {
		log.Message = fmt.Sprintf("DNS error: %v", err)
		l.Println(log.Message)
		if err = h.CreateLogEntry(log); err != nil {
			l.Println(err)
		}
		c.String(http.StatusBadRequest, "dnserr\n")
		return
	}

	// Update DB host entry
	log.Host.Ip = log.SentIP
	log.Host.LastUpdate = log.TimeStamp

	if err = h.DB.Save(log.Host).Error; err != nil {
		c.JSON(http.StatusBadRequest, "badrequest\n")
		return
	}

	log.Status = true
	log.Message = "No errors occurred"
	if err = h.CreateLogEntry(log); err != nil {
		l.Println(err)
	}

	c.String(http.StatusOK, "good\n")
}

func (h *Handler) checkUniqueHostname(hostname, domain string) error {
	hosts := new([]model.Host)
	if err := h.DB.Where(&model.Host{Hostname: hostname, Domain: domain}).Find(hosts).Error; err != nil {
		return err
	}

	if len(*hosts) > 0 {
		return fmt.Errorf("hostname already exists")
	}

	cnames := new([]model.CName)
	if err := h.DB.Preload("Target").Where(&model.CName{Hostname: hostname}).Find(cnames).Error; err != nil {
		return err
	}

	for _, cname := range *cnames {
		if cname.Target.Domain == domain {
			return fmt.Errorf("hostname already exists")
		}
	}

	return nil
}
