package handler

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/benjaminbear/docker-ddns-server/dyndns/model"
	"github.com/gin-gonic/gin"
)

// CreateLogEntry simply adds a log entry to the database.
func (h *Handler) CreateLogEntry(log *model.Log) (err error) {
	if err = h.DB.Create(log).Error; err != nil {
		return err
	}

	return nil
}

// ShowLogs fetches all log entries from all hosts and renders them to the website.
func (h *Handler) ShowLogs(c *gin.Context) {
	if !h.AuthAdmin {
		c.JSON(http.StatusUnauthorized, &Error{UNAUTHORIZED})
		return
	}

	logs := new([]model.Log)
	if err := h.DB.Preload("Host").Limit(30).Order("created_at desc").Find(logs).Error; err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	c.HTML(http.StatusOK, "listlogs", gin.H{
		"logs":  logs,
		"title": h.Title,
	})
}

// ShowHostLogs fetches all log entries of a specific host by "id" and renders them to the website.
func (h *Handler) ShowHostLogs(c *gin.Context) {
	if !h.AuthAdmin {
		c.JSON(http.StatusUnauthorized, &Error{UNAUTHORIZED})
		return
	}

	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	logs := new([]model.Log)
	if err = h.DB.Preload("Host").Where(&model.Log{HostID: uint(id)}).Order("created_at desc").Limit(30).Find(logs).Error; err != nil {
		c.JSON(http.StatusBadRequest, &Error{err.Error()})
		return
	}

	c.HTML(http.StatusOK, "listlogs", gin.H{
		"logs":  logs,
		"title": h.Title,
	})
}

func (h *Handler) ClearLogs() {
	var clearInterval = strconv.FormatUint(h.ClearInterval, 10) + " day"
	h.DB.Exec("DELETE FROM LOGS WHERE created_at < datetime('now', '-" + clearInterval + "');REINDEX LOGS;")
	h.LastClearedLogs = time.Now()
	log.Print("logs cleared")
}
