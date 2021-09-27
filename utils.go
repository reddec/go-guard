package guard

import (
	"net/http"
	"strings"
)

type Router struct {
	*http.ServeMux
	protected http.Handler
	ui        http.Handler
}

func (router *Router) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if strings.HasPrefix(request.URL.Path, "/admin/") {
		router.ui.ServeHTTP(writer, request)
		return
	}
	router.protected.ServeHTTP(writer, request)
}

// Router for requests, where all requests are restricted and ui installed to /admin/.
// Its basic wrapper on http/ServeMux for convenience.
func (g *Guard) Router() *Router {
	mux := http.NewServeMux()
	return &Router{
		ServeMux:  mux,
		ui:        http.StripPrefix("/admin", g.UI()),
		protected: g.Restrict(mux),
	}
}
