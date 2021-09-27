package guard

import "context"

type ContextKey string

const (
	KeyToken ContextKey = "token"
	KeyUser  ContextKey = "user"
)

func withToken(ctx context.Context, token *Token) context.Context {
	return context.WithValue(ctx, KeyToken, token)
}

func withUser(ctx context.Context, user *User) context.Context {
	return context.WithValue(ctx, KeyUser, user)
}

// UserFromContext returns user saved in the context or nil.
func UserFromContext(ctx context.Context) *User {
	u, ok := ctx.Value(KeyUser).(*User)
	if !ok {
		return nil
	}
	return u
}

// TokenFromContext returns token saved in the context or nil.
func TokenFromContext(ctx context.Context) *Token {
	u, ok := ctx.Value(KeyToken).(*Token)
	if !ok {
		return nil
	}
	return u
}
