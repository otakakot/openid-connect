package core

const CookeyState = "__state__"

type State struct {
	ResponseType string
	ClientID     string
	RedirectURI  string
	Scope        string
	State        string
}
