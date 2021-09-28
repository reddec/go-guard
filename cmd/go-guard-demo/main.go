package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"time"

	"github.com/reddec/go-guard"
)

func main() {
	bind := flag.String("bind", "127.0.0.1:8080", "Binding address")
	flag.Parse()

	g := guard.InMemory()

	router := g.Router()

	router.Zone("users").HandleFunc("/users", func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("users only"))
	})

	router.Zone("bot").HandleFunc("/bots", func(writer http.ResponseWriter, request *http.Request) {
		_, _ = writer.Write([]byte("bots only"))
	})

	router.Restricted().HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		var enc = json.NewEncoder(writer)
		enc.SetIndent("", " ")
		writer.Header().Set("Content-Type", "application/json")

		if t := guard.TokenFromContext(request.Context()); t != nil {
			_ = enc.Encode(t)
			return
		}

		if u := guard.UserFromContext(request.Context()); u != nil {
			_ = enc.Encode(u)
			return
		}
	})

	_ = g.CreateUserIfNotExists(context.TODO(), "admin", "admin", nil)
	_ = g.CreateUserIfNotExists(context.TODO(), "demo", "demo", []string{guard.ZoneDefault})
	_ = g.Tokens().Set(context.TODO(), guard.MustToken("demo-token", nil, time.Hour))
	fmt.Println("serving on http://" + *bind)
	fmt.Println("admin UI on http://" + *bind + "/admin/")
	panic(http.ListenAndServe(*bind, router))
}
