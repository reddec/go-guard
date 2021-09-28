package guard

import (
	"net/http"
)

type Router struct {
	*http.ServeMux
	guard     *Guard
	protected http.Handler
}

func (router *Router) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if p := router.protected; p != nil {
		router.protected.ServeHTTP(writer, request)
		return
	}
	router.ServeMux.ServeHTTP(writer, request)
}

func (router *Router) Zone(name string) *Router {
	return &Router{
		ServeMux:  router.ServeMux,
		guard:     router.guard,
		protected: router.guard.RestrictNamed(name, router.ServeMux),
	}
}

// Restricted is alis to Zone(ZoneDefault).
func (router *Router) Restricted() *Router {
	return router.Zone(ZoneDefault)
}

// Router for requests with named restriction zone.
// Root requests are not restricted. UI included with restriction to ZoneAdmin on /admin.
// It's basically wrapper on to of http.ServeMux for convenience.
func (g *Guard) Router() *Router {
	mux := http.NewServeMux()
	mux.Handle("/admin/", http.StripPrefix("/admin", g.UI()))
	return &Router{
		ServeMux: mux,
		guard:    g,
	}
}
