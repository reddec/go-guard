package guard

import (
	_ "embed"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed templates/index.gohtml
var mainTemplateContent string

func (g *Guard) getMain(writer http.ResponseWriter, request *http.Request) {
	type response struct {
		Users  []User
		Tokens []Token
		Zones  []string
		Error  string
		Now    time.Time
		Second time.Duration
	}

	ctx := request.Context()
	users, err := g.users.List(ctx)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	tokens, err := g.tokens.List(ctx)
	if err != nil {
		http.Error(writer, err.Error(), http.StatusInternalServerError)
		return
	}
	zones := g.Zones()
	sort.Slice(users, func(i, j int) bool {
		return users[i].Name < users[j].Name
	})
	sort.Slice(tokens, func(i, j int) bool {
		if tokens[i].Label == tokens[j].Label {
			return tokens[i].CreatedAt.Before(tokens[j].CreatedAt)
		}
		return tokens[i].Label < tokens[j].Label
	})
	sort.Strings(zones)
	writer.Header().Set("Content-Type", "text/html")
	writer.WriteHeader(http.StatusOK)
	err = g.templates.main.Execute(writer, response{
		Users:  users,
		Tokens: tokens,
		Zones:  zones,
		Error:  request.URL.Query().Get("error"),
		Now:    time.Now(),
		Second: time.Second,
	})
	if err != nil {
		//TODO: log
	}
}

func (g *Guard) postTokens(writer http.ResponseWriter, request *http.Request) {
	switch request.FormValue("action") {
	case "create":
		label := request.FormValue("label")
		zones := clearSlice(strings.Split(request.FormValue("zones"), ","))
		durationRaw := request.FormValue("duration")
		var duration time.Duration
		if v, err := time.ParseDuration(durationRaw); durationRaw != "" && err != nil {
			redirectBack(writer, err)
			return
		} else {
			duration = v
		}
		token := MustToken(label, zones, duration)
		redirectBack(writer, g.tokens.Set(request.Context(), token))
	case "delete":
		value := request.FormValue("value")
		redirectBack(writer, g.tokens.Delete(request.Context(), value))
	}
}

func (g *Guard) postBasic(writer http.ResponseWriter, request *http.Request) {
	name := request.FormValue("name")
	switch request.FormValue("action") {
	case "create":
		password := request.FormValue("password")
		active := request.FormValue("active") == "on"
		zones := clearSlice(strings.Split(request.FormValue("zones"), ","))
		user := MustUser(name, password, zones)
		user.Disabled = !active
		redirectBack(writer, g.users.Set(request.Context(), user))
	case "delete":
		redirectBack(writer, g.users.Delete(request.Context(), name))
	case "reset-password":
		u, err := g.users.Get(request.Context(), name)
		if err != nil {
			redirectBack(writer, err)
			return
		}
		err = u.Password(request.FormValue("password"))
		if err != nil {
			redirectBack(writer, err)
			return
		}
		u.UpdatedAt = time.Now()

		redirectBack(writer, g.users.Set(request.Context(), u))
	case "change-status":
		u, err := g.users.Get(request.Context(), name)
		if err != nil {
			redirectBack(writer, err)
			return
		}

		status, err := strconv.ParseBool(request.FormValue("nextStatus"))
		if err != nil {
			redirectBack(writer, err)
			return
		}
		u.Disabled = status
		u.UpdatedAt = time.Now()

		redirectBack(writer, g.users.Set(request.Context(), u))
	}
}

func redirectBack(writer http.ResponseWriter, err error) {
	q := ""
	if err != nil {
		q = "error=" + url.QueryEscape(err.Error())
	}
	writer.Header().Set("Location", "./?"+q)
	writer.WriteHeader(http.StatusSeeOther)
}

func clearSlice(slice []string) []string {
	cp := make([]string, 0, len(slice))
	for _, v := range slice {
		v = strings.TrimSpace(v)
		if len(v) > 0 {
			cp = append(cp, v)
		}
	}
	return cp
}
