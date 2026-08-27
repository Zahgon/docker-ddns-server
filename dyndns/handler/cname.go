package handler

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/benjaminbear/docker-ddns-server/dyndns/model"
	"github.com/benjaminbear/docker-ddns-server/dyndns/nswrapper"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// ListCNames fetches all cnames from database and lists them on the website.
func (h *Handler) ListCNames(c *gin.Context) {
	if !h.AuthAdmin {
		c.JSON(http.StatusUnauthorized, &Error{UNAUTHORIZED})
		return
	}

	cnames := new([]model.CName)
	if err := h.DB.Preload("Target").Find(cnames).Error; err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	c.HTML(http.StatusOK, "listcnames", gin.H{
		"cnames": cnames,
		"title":  h.Title,
	})
}

// AddCName just renders the "add cname" website.
// Therefore all host entries from the database are being fetched.
func (h *Handler) AddCName(c *gin.Context) {
	if !h.AuthAdmin {
		c.JSON(http.StatusUnauthorized, &Error{UNAUTHORIZED})
		return
	}

	hosts := new([]model.Host)
	if err := h.DB.Find(hosts).Error; err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	c.HTML(http.StatusOK, "addcname", gin.H{
		"config": h.Config,
		"hosts":  hosts,
		"title":  h.Title,
	})
}

// CreateCName validates the cname data from the "add cname" website,
// adds the cname entry to the database,
// and adds the entry to the DNS server.
func (h *Handler) CreateCName(c *gin.Context) {
	if !h.AuthAdmin {
		c.JSON(http.StatusUnauthorized, &Error{UNAUTHORIZED})
		return
	}

	cname := &model.CName{}
	if err := c.ShouldBind(cname); err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	// echo's c.FormValue read the posted form first and fell back to the query string.
	targetID := c.PostForm("target_id")
	if targetID == "" {
		targetID = c.Query("target_id")
	}

	host := &model.Host{}
	if err := h.DB.First(host, targetID).Error; err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	cname.Target = *host

	if err := h.Validate(cname); err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	if err := h.checkUniqueHostname(cname.Hostname, cname.Target.Domain); err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	if err := h.DB.Create(cname).Error; err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	if err := nswrapper.UpdateRecord(cname.Hostname, fmt.Sprintf("%s.%s", cname.Target.Hostname, cname.Target.Domain), "CNAME", cname.Target.Domain, cname.Ttl, h.AllowWildcard); err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	c.JSON(http.StatusOK, cname)
}

// DeleteCName fetches a cname entry from the database by "id"
// and deletes the database and DNS server entry to it.
func (h *Handler) DeleteCName(c *gin.Context) {
	if !h.AuthAdmin {
		c.JSON(http.StatusUnauthorized, &Error{UNAUTHORIZED})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	cname := &model.CName{}
	if err = h.DB.Preload("Target").First(cname, id).Error; err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	err = h.DB.Transaction(func(tx *gorm.DB) error {
		if err = tx.Unscoped().Delete(cname).Error; err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	if err = nswrapper.DeleteRecord(cname.Hostname, cname.Target.Domain, h.AllowWildcard); err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	c.JSON(http.StatusOK, id)
}
