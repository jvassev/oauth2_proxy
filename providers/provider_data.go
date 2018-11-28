package providers

import (
	"net/url"
)

type ProviderData struct {
	ProviderName      string
	ClientID          string
	ClientSecret      string
	LoginURL          *url.URL
	RedeemURL         *url.URL
	ProfileURL        *url.URL
	ProtectedResource *url.URL
	ValidateURL       *url.URL
	Scope             string
	ApprovalPrompt    string

	GazIdpId     string
	GazContextId string
	ExtraHeaders []string
}

func (p *ProviderData) Data() *ProviderData { return p }

type ClientDataGetter func() (string, string)
