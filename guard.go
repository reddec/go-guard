// Package guard protects application by tokens and basic auth.
package guard

import (
	"bytes"
	"context"
	cryptoRand "crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math/rand"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	ZoneDefault = "default"
	ZoneAdmin   = "admin"
	KindToken   = "token"
	KindBasic   = "basic"
	DefaultKind = KindToken
	AuthQuery   = "token" // query parameter for credentials
)

const SaltSize = 32 // bytes

type User struct {
	Name      string    `json:"name"`               // unique name of user
	Hash      []byte    `json:"hash"`               // hashed (SHA-512 with salt) password
	Salt      []byte    `json:"salt"`               // salt from cryptographic random source
	CreatedAt time.Time `json:"created_at"`         // creation time
	UpdatedAt time.Time `json:"updated_at"`         // last modification time
	Disabled  bool      `json:"disabled,omitempty"` // disable login
	Zones     []string  `json:"zones,omitempty"`    // allowed zones. Empty means that allowed everything.
}

func NewUser(name, password string, zones []string) (*User, error) {
	now := time.Now()
	u := User{
		Name:      name,
		CreatedAt: now,
		UpdatedAt: now,
		Zones:     zones,
	}
	return &u, u.Password(password)
}

func MustUser(name, password string, zones []string) *User {
	u, err := NewUser(name, password, zones)
	if err != nil {
		panic(err)
	}
	return u
}

func (u *User) Check(password string) bool {
	hasher := sha512.New()
	if _, err := hasher.Write(u.Salt); err != nil {
		return false
	}
	hash := hasher.Sum([]byte(password))
	return bytes.Equal(hash, u.Hash)
}

func (u *User) Password(password string) error {
	var salt [SaltSize]byte
	if _, err := io.ReadFull(cryptoRand.Reader, salt[:]); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}

	hasher := sha512.New()
	if _, err := hasher.Write(salt[:]); err != nil {
		return fmt.Errorf("add salt: %w", err)
	}
	u.Hash = hasher.Sum([]byte(password))
	u.Salt = salt[:]
	return nil
}

const TokenSize = 32 // bytes

type Token struct {
	Label     string    `json:"label,omitempty"`      // optional human-readable token description.
	Value     string    `json:"value"`                // unique 256-bit random value for crypto source in HEX.
	Zones     []string  `json:"zones,omitempty"`      // allowed zones. Empty means that allowed everything.
	CreatedAt time.Time `json:"created_at"`           // creation time
	ExpiredAt time.Time `json:"expired_at,omitempty"` // optional expiration time
}

func NewToken(label string, zones []string, duration time.Duration) (*Token, error) {
	var buffer [TokenSize]byte
	if _, err := io.ReadFull(cryptoRand.Reader, buffer[:]); err != nil {
		return nil, fmt.Errorf("read random data: %w", err)
	}
	value := hex.EncodeToString(buffer[:])
	token := Token{
		Label:     label,
		Value:     value,
		Zones:     zones,
		CreatedAt: time.Now(),
	}
	if duration > 0 {
		token.ExpiredAt = token.CreatedAt.Add(duration)
	}
	return &token, nil
}

func MustToken(label string, zones []string, duration time.Duration) *Token {
	t, err := NewToken(label, zones, duration)
	if err != nil {
		panic(err)
	}
	return t
}

type Guard struct {
	requestBasic bool
	users        UserStorage
	tokens       TokenStorage
	maxDelay     time.Duration
	zones        struct {
		set  map[string]bool
		lock sync.RWMutex
	}
	templates struct {
		main *template.Template
	}
}

func New(users UserStorage, tokens TokenStorage) *Guard {
	g := &Guard{
		users:        users,
		tokens:       tokens,
		maxDelay:     10 * time.Second,
		requestBasic: true,
	}
	g.templates.main = template.Must(template.New("").Parse(mainTemplateContent))
	return g
}

// Persistent guard with file-based storages.
func Persistent(directory string) *Guard {
	return New(&FileUserStorage{
		Directory: filepath.Join(directory, "users"),
	}, &FileTokenStorage{
		Directory: filepath.Join(directory, "tokens"),
	})
}

// InMemory guard with in-memory only storages. All data will be lost after restart.
func InMemory() *Guard {
	return New(&MemoryUserStorage{}, &MemoryTokenStorage{})
}

// Delay (maximum) for response on invalid login attempt.
// Will be used random value between 0 and provided duration (exclusive).
func (g *Guard) Delay(max time.Duration) *Guard {
	g.maxDelay = max
	return g
}

// Basic auth request response (ie: www-authenticate) in case of unauthorized (without credentials)
// request to restricted zone. Useful to show login prompt in browsers. Enabled by default.
func (g *Guard) Basic(enable bool) *Guard {
	g.requestBasic = enable
	return g
}

// Tokens storage same as defined during creation.
func (g *Guard) Tokens() TokenStorage {
	return g.tokens
}

// Users storage same as defined during creation.
func (g *Guard) Users() UserStorage {
	return g.users
}

// UI handler with restriction 'admin' zone. Prefix should be stripped.
func (g *Guard) UI() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", g.getMain)
	mux.HandleFunc("/tokens", g.postTokens)
	mux.HandleFunc("/users", g.postBasic)

	return g.RestrictNamed(ZoneAdmin, mux)
}

// CreateUserIfNotExists creates user if not exists with initial password. Doesn't modify existent user.
// Thread unsafe.
func (g *Guard) CreateUserIfNotExists(ctx context.Context, name string, initialPassword string, zones []string) error {
	_, err := g.users.Get(ctx, name)
	if err == nil || !errors.Is(err, ErrUserNotFound) {
		return err
	}

	u, err := NewUser(name, initialPassword, zones)
	if err != nil {
		return err
	}

	return g.users.Set(ctx, u)
}

// Restrict handler. Same as RestrictNamed with ZoneDefault as name.
func (g *Guard) Restrict(handler http.Handler) http.Handler {
	return g.RestrictNamed(ZoneDefault, handler)
}

// RestrictNamed protects handler by requiring authorization for each request.
func (g *Guard) RestrictNamed(zoneName string, handler http.Handler) http.Handler {
	g.saveZone(zoneName)

	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		request.BasicAuth()
		token, kind, ok := parseToken(request)
		if !ok {
			if g.requestBasic {
				g.requestBasicAuth(writer)
				return
			}
			http.Error(writer, "restricted", http.StatusUnauthorized)
			return
		}

		ctx, allowed := g.isAllowed(request.Context(), zoneName, kind, token)
		if !allowed {
			time.Sleep(1 + time.Duration(rand.Int63n(int64(g.maxDelay))))
			if g.requestBasic {
				g.requestBasicAuth(writer)
				return
			}
			http.Error(writer, "restricted", http.StatusUnauthorized)
			return
		}

		handler.ServeHTTP(writer, request.WithContext(ctx))
	})
}

// Zones names. Copy.
func (g *Guard) Zones() []string {
	g.zones.lock.RLock()
	defer g.zones.lock.RUnlock()
	cp := make([]string, 0, len(g.zones.set))
	for zone := range g.zones.set {
		cp = append(cp, zone)
	}
	return cp
}

func (g *Guard) isAllowed(ctx context.Context, zone string, kind, token string) (context.Context, bool) {
	switch kind {
	case KindToken:
		return g.authByToken(ctx, zone, token)
	case KindBasic:
		return g.authByBasic(ctx, zone, token)
	}
	return nil, false
}

func (g *Guard) authByBasic(ctx context.Context, zone string, token string) (context.Context, bool) {
	val, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return nil, false
	}
	creds := string(val)
	s := strings.IndexByte(creds, ':')
	if s < 0 {
		return nil, false
	}
	user := creds[:s]
	pass := creds[s+1:]
	userInfo, err := g.users.Get(ctx, user)
	if err != nil {
		//TODO: add log
		return nil, false
	}

	if userInfo.Disabled {
		return nil, false
	}

	if !userInfo.Check(pass) {
		return nil, false
	}

	if !g.isZoneAllowed(zone, userInfo.Zones) {
		return nil, false
	}
	return withUser(ctx, userInfo), true
}

func (g *Guard) authByToken(ctx context.Context, zone string, token string) (context.Context, bool) {
	saved, err := g.tokens.Get(ctx, token)
	if err != nil {
		return nil, false
	}

	if !saved.ExpiredAt.IsZero() && time.Now().After(saved.ExpiredAt) {
		return nil, false
	}

	if !g.isZoneAllowed(zone, saved.Zones) {
		return nil, false
	}
	return withToken(ctx, saved), true
}

func (g *Guard) isZoneAllowed(zone string, allowed []string) bool {
	if len(allowed) == 0 {
		return true
	}

	for _, allowedZone := range allowed {
		if allowedZone == zone {
			return true
		}
	}

	return false
}

func (g *Guard) saveZone(zoneName string) {
	g.zones.lock.Lock()
	if g.zones.set == nil {
		g.zones.set = make(map[string]bool)
	}
	g.zones.set[zoneName] = true
	g.zones.lock.Unlock()
}

func (g *Guard) requestBasicAuth(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="Restricted zone"`)
	w.WriteHeader(401)
	_, _ = w.Write([]byte("Unauthorised.\n"))
}

func parseToken(request *http.Request) (string, string, bool) {
	token := request.Header.Get("Authorization")
	if token == "" {
		token = request.Header.Get("X-Api-Token")
	}
	if token == "" {
		token = request.URL.Query().Get(AuthQuery)
	}
	kind := DefaultKind
	parts := strings.SplitN(strings.TrimSpace(token), " ", 2)
	if len(parts) == 2 {
		kind = strings.ToLower(strings.TrimSpace(parts[0]))
		token = strings.TrimSpace(parts[1])
	}
	return token, kind, len(token) > 0
}
