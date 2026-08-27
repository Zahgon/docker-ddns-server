package main

import (
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/benjaminbear/docker-ddns-server/dyndns/handler"
	"github.com/foolin/goview"
	"github.com/foolin/goview/supports/ginview"
	"github.com/gin-gonic/gin"
)

// redirect sends the Location header verbatim like echo's c.Redirect did.
// gin's c.Redirect delegates to http.Redirect, which rewrites a relative
// Location into an absolute one and appends an HTML body.
func redirect(c *gin.Context, code int, url string) {
	c.Header("Location", url)
	c.AbortWithStatus(code)
}

func setupRouter(h *handler.Handler, authAdmin bool) *gin.Engine {
	router := gin.New()
	router.Use(gin.Logger(), gin.Recovery())

	// Set Renderer
	router.HTMLRender = ginview.New(goview.Config{
		Root:      "views",
		Master:    "layouts/master",
		Extension: ".html",
		Funcs: template.FuncMap{
			"year": func() string {
				return time.Now().Format("2006")
			},
		},
		DisableCache: true,
	})

	// Set Statics
	router.Static("/static", "static")

	// UI Routes
	redirectToAdmin := func(c *gin.Context) {
		//redirect to admin
		redirect(c, 301, "./admin/")
	}
	router.GET("/", redirectToAdmin)
	router.NoRoute(redirectToAdmin)

	groupAdmin := router.Group("/admin")
	if authAdmin {
		groupAdmin.Use(h.BasicAuthAdmin())
	}

	groupAdmin.GET("/", h.ListHosts)
	groupAdmin.GET("/hosts/add", h.AddHost)
	groupAdmin.GET("/hosts/edit/:id", h.EditHost)
	groupAdmin.GET("/hosts", h.ListHosts)
	groupAdmin.GET("/cnames/add", h.AddCName)
	groupAdmin.GET("/cnames", h.ListCNames)
	groupAdmin.GET("/logs", h.ShowLogs)
	groupAdmin.GET("/logs/host/:id", h.ShowHostLogs)

	// Rest Routes
	groupAdmin.POST("/hosts/add", h.CreateHost)
	groupAdmin.POST("/hosts/edit/:id", h.UpdateHost)
	groupAdmin.GET("/hosts/delete/:id", h.DeleteHost)
	//redirect to logout
	groupAdmin.GET("/logout", func(c *gin.Context) {
		// either custom url
		if len(h.LogoutUrl) > 0 {
			redirect(c, 302, h.LogoutUrl)
			return
		}
		// or standard url
		redirect(c, 302, "../")
	})
	groupAdmin.POST("/cnames/add", h.CreateCName)
	groupAdmin.GET("/cnames/delete/:id", h.DeleteCName)

	// dyndns compatible api
	// (avoid breaking changes and create groups for each update endpoint)
	updateRoute := router.Group("/update")
	updateRoute.Use(h.BasicAuthUpdate())
	updateRoute.GET("", h.UpdateIP)
	nicRoute := router.Group("/nic")
	nicRoute.Use(h.BasicAuthUpdate())
	nicRoute.GET("/update", h.UpdateIP)
	v2Route := router.Group("/v2")
	v2Route.Use(h.BasicAuthUpdate())
	v2Route.GET("/update", h.UpdateIP)
	v3Route := router.Group("/v3")
	v3Route.Use(h.BasicAuthUpdate())
	v3Route.GET("/update", h.UpdateIP)

	// health-check
	router.GET("/ping", func(c *gin.Context) {
		u := &handler.Error{
			Message: "OK",
		}
		c.JSON(http.StatusOK, u)
	})

	return router
}

func main() {
	// Initialize handler
	h := &handler.Handler{}

	// Database connection
	if err := h.InitDB(); err != nil {
		log.Fatal(err)
	}

	authAdmin, err := h.ParseEnvs()
	if err != nil {
		log.Fatal(err)
	}

	router := setupRouter(h, authAdmin)

	// Start server
	log.Fatal(router.Run(":8080"))
}
