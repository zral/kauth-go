package auth_test

import (
	"testing"
	"time"

	"github.com/zral/kauth-go/internal/auth"
)

func TestRateLimiter_BlocksAfterThreeAttempts(t *testing.T) {
	rl := auth.NewRateLimiter(3, 15*time.Minute)
	email := "test@example.com"
	if !rl.Allow(email) {
		t.Fatal("første forsøk skal være tillatt")
	}
	if !rl.Allow(email) {
		t.Fatal("andre forsøk skal være tillatt")
	}
	if !rl.Allow(email) {
		t.Fatal("tredje forsøk skal være tillatt")
	}
	if rl.Allow(email) {
		t.Fatal("fjerde forsøk skal blokkeres")
	}
}

func TestRateLimiter_DifferentEmailsAreIndependent(t *testing.T) {
	rl := auth.NewRateLimiter(3, 15*time.Minute)
	for i := 0; i < 3; i++ {
		rl.Allow("a@example.com")
	}
	if !rl.Allow("b@example.com") {
		t.Fatal("annen e-post skal ikke påvirkes")
	}
}

func TestRateLimiter_ExpiresAfterWindow(t *testing.T) {
	rl := auth.NewRateLimiter(1, 50*time.Millisecond)
	if !rl.Allow("x@example.com") {
		t.Fatal("første forsøk")
	}
	if rl.Allow("x@example.com") {
		t.Fatal("skal blokkeres")
	}
	time.Sleep(100 * time.Millisecond)
	if !rl.Allow("x@example.com") {
		t.Fatal("etter vinduet skal det gå")
	}
}
