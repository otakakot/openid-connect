// Package api provides primitives to interact with the openapi HTTP API.
//
// Code generated by github.com/oapi-codegen/oapi-codegen/v2 version v2.3.0 DO NOT EDIT.
package api

const (
	BearerScopes = "Bearer.Scopes"
)

// Defines values for AuthorizeErrorType.
const (
	AuthorizeErrorTypeAccessDenied            AuthorizeErrorType = "access_denied"
	AuthorizeErrorTypeInvalidRequest          AuthorizeErrorType = "invalid_request"
	AuthorizeErrorTypeInvalidScope            AuthorizeErrorType = "invalid_scope"
	AuthorizeErrorTypeServerError             AuthorizeErrorType = "server_error"
	AuthorizeErrorTypeTemporarilyUnavailable  AuthorizeErrorType = "temporarily_unavailable"
	AuthorizeErrorTypeUnauthorizedClient      AuthorizeErrorType = "unauthorized_client"
	AuthorizeErrorTypeUnsupportedResponseType AuthorizeErrorType = "unsupported_response_type"
)

// Defines values for TokenErrorType.
const (
	TokenErrorTypeInvalidClient        TokenErrorType = "invalid_client"
	TokenErrorTypeInvalidGrant         TokenErrorType = "invalid_grant"
	TokenErrorTypeInvalidRequest       TokenErrorType = "invalid_request"
	TokenErrorTypeInvalidScope         TokenErrorType = "invalid_scope"
	TokenErrorTypeUnauthorizedClient   TokenErrorType = "unauthorized_client"
	TokenErrorTypeUnsupportedGrantType TokenErrorType = "unsupported_grant_type"
)

// Defines values for TokenRequestSchemaGrantType.
const (
	TokenRequestSchemaGrantTypeAuthorizationCode TokenRequestSchemaGrantType = "authorization_code"
	TokenRequestSchemaGrantTypeRefreshToken      TokenRequestSchemaGrantType = "refresh_token"
)

// Defines values for AuthorizeParamsResponseType.
const (
	Code AuthorizeParamsResponseType = "code"
)

// Defines values for AuthorizeParamsScope.
const (
	Openid AuthorizeParamsScope = "openid"
)

// Defines values for RevokeFormdataBodyTokenTypeHint.
const (
	RevokeFormdataBodyTokenTypeHintAccessToken  RevokeFormdataBodyTokenTypeHint = "access_token"
	RevokeFormdataBodyTokenTypeHintRefreshToken RevokeFormdataBodyTokenTypeHint = "refresh_token"
)

// AuthorizeErrorType defines model for AuthorizeErrorType.
type AuthorizeErrorType string

// CertsResponseSchema defines model for CertsResponseSchema.
type CertsResponseSchema struct {
	Keys []JWKSet `json:"keys"`
}

// JWKSet defines model for JWKSet.
type JWKSet struct {
	Alg string `json:"alg"`
	E   string `json:"e"`
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	Use string `json:"use"`
}

// OpenIDConfigurationResponseSchema https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
type OpenIDConfigurationResponseSchema struct {
	// AuthorizationEndpoint http://localhost:8787/authorize
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`

	// Issuer http://localhost:8787
	Issuer string `json:"issuer"`

	// JwksUri http://localhost:8787/certs
	JwksUri string `json:"jwks_uri"`

	// RevocationEndpoint http://localhost:8787/revoke
	RevocationEndpoint    string   `json:"revocation_endpoint"`
	SubjectTypesSupported []string `json:"subject_types_supported"`

	// TokenEndpoint http://localhost:8787/token
	TokenEndpoint string `json:"token_endpoint"`

	// UserinfoEndpoint http://localhost:8787/userinfo
	UserinfoEndpoint string `json:"userinfo_endpoint"`
}

// TokenErrorSchema defines model for TokenErrorSchema.
type TokenErrorSchema struct {
	Error            TokenErrorType `json:"error"`
	ErrorDescription *string        `json:"error_description,omitempty"`
	ErrorUri         *string        `json:"error_uri,omitempty"`
}

// TokenErrorType defines model for TokenErrorType.
type TokenErrorType string

// TokenRequestSchema defines model for TokenRequestSchema.
type TokenRequestSchema struct {
	// ClientAssertion needs when grant_type is authorization_code. ref https://datatracker.ietf.org/doc/html/rfc7523#section-2.2
	ClientAssertion *string `json:"client_assertion,omitempty"`

	// ClientId needs when grant_type is authorization_code
	ClientId *string `json:"client_id,omitempty"`

	// ClientSecret needs when grant_type is authorization_code
	ClientSecret *string `json:"client_secret,omitempty"`

	// Code needs when grant_type is authorization_code
	Code *string `json:"code,omitempty"`

	// GrantType grant_type
	GrantType TokenRequestSchemaGrantType `json:"grant_type"`

	// RedirectUri neews when grant_type is authorization_code
	RedirectUri *string `json:"redirect_uri,omitempty"`

	// RefreshToken needs when grant_type is refresh_token
	RefreshToken *string `json:"refresh_token,omitempty"`

	// Scope optional
	Scope *string `json:"scope,omitempty"`
}

// TokenRequestSchemaGrantType grant_type
type TokenRequestSchemaGrantType string

// TokenResponseSchema https://openid-foundation-japan.github.io/openid-connect-core-1_0.ja.html#TokenResponse
type TokenResponseSchema struct {
	// AccessToken access_token
	AccessToken string `json:"access_token"`

	// ExpiresIn expires_in
	ExpiresIn int `json:"expires_in"`

	// IdToken id_token
	IdToken string `json:"id_token"`

	// RefreshToken refresh_token
	RefreshToken string `json:"refresh_token"`

	// TokenType token_type
	TokenType string `json:"token_type"`
}

// UserInfoResponseSchema defines model for UserInfoResponseSchema.
type UserInfoResponseSchema struct {
	Email string `json:"email"`
	Sub   string `json:"sub"`
}

// AuthorizeParams defines parameters for Authorize.
type AuthorizeParams struct {
	// ResponseType response_type
	ResponseType AuthorizeParamsResponseType `form:"response_type" json:"response_type"`

	// ClientId client_id
	ClientId string `form:"client_id" json:"client_id"`

	// RedirectUri http://localhost:8080/callback
	RedirectUri *string `form:"redirect_uri,omitempty" json:"redirect_uri,omitempty"`

	// Scope openid
	Scope *AuthorizeParamsScope `form:"scope,omitempty" json:"scope,omitempty"`

	// State state
	State *string `form:"state,omitempty" json:"state,omitempty"`
}

// AuthorizeParamsResponseType defines parameters for Authorize.
type AuthorizeParamsResponseType string

// AuthorizeParamsScope defines parameters for Authorize.
type AuthorizeParamsScope string

// CallbackParams defines parameters for Callback.
type CallbackParams struct {
	// Id id
	Id string `form:"id" json:"id"`
}

// LoginViewParams defines parameters for LoginView.
type LoginViewParams struct {
	// Id id
	Id string `form:"id" json:"id"`
}

// LoginFormdataBody defines parameters for Login.
type LoginFormdataBody struct {
	Email    *string `form:"email,omitempty" json:"email,omitempty"`
	Password *string `form:"password,omitempty" json:"password,omitempty"`
}

// RevokeFormdataBody defines parameters for Revoke.
type RevokeFormdataBody struct {
	Token         string                           `form:"token" json:"token"`
	TokenTypeHint *RevokeFormdataBodyTokenTypeHint `form:"token_type_hint,omitempty" json:"token_type_hint,omitempty"`
}

// RevokeFormdataBodyTokenTypeHint defines parameters for Revoke.
type RevokeFormdataBodyTokenTypeHint string

// LoginFormdataRequestBody defines body for Login for application/x-www-form-urlencoded ContentType.
type LoginFormdataRequestBody LoginFormdataBody

// RevokeFormdataRequestBody defines body for Revoke for application/x-www-form-urlencoded ContentType.
type RevokeFormdataRequestBody RevokeFormdataBody

// TokenFormdataRequestBody defines body for Token for application/x-www-form-urlencoded ContentType.
type TokenFormdataRequestBody = TokenRequestSchema
