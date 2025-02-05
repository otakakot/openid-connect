package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"reflect"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/otakakot/openid-connect/internal/token"
)

func TestGenerateAccessToken(t *testing.T) {
	t.Parallel()

	type args struct {
		iss string
		sub string
	}

	tests := []struct {
		name string
		args args
		want token.AccessToken
	}{
		{
			name: "success",
			args: args{
				iss: "issuer@example.com",
				sub: "test",
			},
			want: token.AccessToken{
				Iss: "issuer@example.com",
				Sub: "test",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := token.GenerateAccessToken(tt.args.iss, tt.args.sub)

			if !reflect.DeepEqual(got.Sub, tt.want.Sub) {
				t.Errorf("GenerateAccessToken() = %v, want %v", got.Sub, tt.want.Sub)
			}

			if !reflect.DeepEqual(got.Iss, tt.want.Iss) {
				t.Errorf("GenerateAccessToken() = %v, want %v", got.Iss, tt.want.Iss)
			}
		})
	}
}

func TestParceAccessToken(t *testing.T) {
	t.Parallel()

	type args struct {
		str  func() string
		sign string
	}

	tests := []struct {
		name    string
		args    args
		want    token.AccessToken
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				str: func() string {
					return token.GenerateAccessToken("test@example.com", "test").JWT("test")
				},
				sign: "test",
			},
			want: token.AccessToken{
				Iss: "test@example.com",
				Sub: "test",
			},
			wantErr: false,
		},
		{
			name: "failed_for_invalid_token",
			args: args{
				str: func() string {
					return "invalid"
				},
				sign: "test",
			},
			want:    token.AccessToken{},
			wantErr: true,
		},
		{
			name: "failed_for_invalid_sign",
			args: args{
				str: func() string {
					return token.GenerateAccessToken("test@example.com", "test").JWT("test")
				},
				sign: "invalid",
			},
			want:    token.AccessToken{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := token.ParceAccessToken(tt.args.str(), tt.args.sign)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParceAccessToken() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if tt.wantErr {
				return
			}

			if !reflect.DeepEqual(got.Sub, tt.want.Sub) {
				t.Errorf("ParceAccessToken() = %v, want %v", got.Sub, tt.want.Sub)
			}

			if !reflect.DeepEqual(got.Iss, tt.want.Iss) {
				t.Errorf("ParceAccessToken() = %v, want %v", got.Iss, tt.want.Iss)
			}
		})
	}
}

func TestGenerateIDToken(t *testing.T) {
	t.Parallel()

	type args struct {
		iss string
		sub string
		aud string
		jti string
	}

	tests := []struct {
		name string
		args args
		want token.IDToken
	}{
		{
			name: "success",
			args: args{
				iss: "issuer@example.com",
				sub: "subject",
				aud: "audience@example.com",
				jti: "jwt_id",
			},
			want: token.IDToken{
				Iss: "issuer@example.com",
				Sub: "subject",
				Aud: "audience@example.com",
				Jti: "jwt_id",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := token.GenerateIDToken(
				tt.args.iss,
				tt.args.sub,
				tt.args.aud,
				tt.args.jti,
			)

			if !reflect.DeepEqual(got.Iss, tt.want.Iss) {
				t.Errorf("GenerateIDToken() = %v, want %v", got.Iss, tt.want.Iss)
			}

			if !reflect.DeepEqual(got.Sub, tt.want.Sub) {
				t.Errorf("GenerateIDToken() = %v, want %v", got.Sub, tt.want.Sub)
			}

			if !reflect.DeepEqual(got.Aud, tt.want.Aud) {
				t.Errorf("GenerateIDToken() = %v, want %v", got.Aud, tt.want.Aud)
			}

			if !reflect.DeepEqual(got.Jti, tt.want.Jti) {
				t.Errorf("GenerateIDToken() = %v, want %v", got.Jti, tt.want.Jti)
			}
		})
	}
}

func TestValidateClientAssertion(t *testing.T) {
	t.Parallel()

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	invalidPrivKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	type args struct {
		tokenStr  func() string
		publicKey *rsa.PublicKey
	}

	tests := []struct {
		name    string
		args    args
		want    *jwt.MapClaims
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				tokenStr: func() string {
					claims := jwt.MapClaims{
						"iss": "client@example.com",
						"sub": "subject",
						"aud": "server@example.com",
						"jti": "jwt_id",
						"exp": time.Now().Add(time.Hour).Unix(),
						"iat": time.Now().Unix(),
					}

					token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
					tokenString, _ := token.SignedString(privKey)

					return tokenString
				},
				publicKey: &privKey.PublicKey,
			},
			want: &jwt.MapClaims{
				"iss": "client@example.com",
				"sub": "subject",
				"aud": "server@example.com",
				"jti": "jwt_id",
			},
			wantErr: false,
		},
		{
			name: "failed_for_invalid_token",
			args: args{
				tokenStr: func() string {
					return "invalid"
				},
				publicKey: &privKey.PublicKey,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "failed_for_invalid_public_key",
			args: args{
				tokenStr: func() string {
					claims := jwt.MapClaims{
						"iss": "client@example.com",
						"sub": "subject",
						"aud": "server@example.com",
						"jti": "jwt_id",
						"exp": time.Now().Add(time.Hour).Unix(),
						"iat": time.Now().Unix(),
					}

					token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
					tokenString, _ := token.SignedString(privKey)

					return tokenString
				},
				publicKey: &invalidPrivKey.PublicKey,
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := token.ValidateClientAssertion(tt.args.tokenStr(), tt.args.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateClientAssertion() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			gotIss, _ := got.GetIssuer()

			wantIss, _ := tt.want.GetIssuer()

			if !reflect.DeepEqual(gotIss, wantIss) {
				t.Errorf("ValidateClientAssertion() = %v, want %v", gotIss, wantIss)
			}

			gotSub, _ := got.GetSubject()

			wantSub, _ := tt.want.GetSubject()

			if !reflect.DeepEqual(gotSub, wantSub) {
				t.Errorf("ValidateClientAssertion() = %v, want %v", gotSub, wantSub)
			}

			gotAud, _ := got.GetAudience()

			wantAud, _ := tt.want.GetAudience()

			if !reflect.DeepEqual(gotAud, wantAud) {
				t.Errorf("ValidateClientAssertion() = %v, want %v", gotAud, wantAud)
			}
		})
	}
}
