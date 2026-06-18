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

func TestSignAndVerifyState_Valid(t *testing.T) {
	secret := []byte("test-secret-32bytes-padded-here!")
	state := auth.SignState(secret, "spekto", "abc123nonce")
	svcID, ok := auth.VerifyState(secret, state)
	if !ok {
		t.Fatal("forventet gyldig state")
	}
	if svcID != "spekto" {
		t.Fatalf("feil serviceID: %q", svcID)
	}
}

func TestVerifyState_WrongSecret(t *testing.T) {
	state := auth.SignState([]byte("riktig-secret-32bytes-padded!!"), "spekto", "nonce")
	_, ok := auth.VerifyState([]byte("feil-secret-32bytes-padded-!!"), state)
	if ok {
		t.Fatal("feil secret skal feile")
	}
}

func TestVerifyState_TamperedPayload(t *testing.T) {
	secret := []byte("secret-32bytes-padded-here-!!!!")
	state := auth.SignState(secret, "spekto", "nonce")
	tampered := state[:len(state)-4] + "XXXX"
	_, ok := auth.VerifyState(secret, tampered)
	if ok {
		t.Fatal("manipulert state skal feile")
	}
}
