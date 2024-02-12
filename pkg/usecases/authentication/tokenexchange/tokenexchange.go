package tokenexchange

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/int128/kubelogin/pkg/oidc/client"
	"net/http"
	"net/url"
	"os"
	"strings"

	gooidc "github.com/coreos/go-oidc/v3/oidc"

	"github.com/int128/kubelogin/pkg/infrastructure/logger"
	"github.com/int128/kubelogin/pkg/oidc"
	"github.com/int128/kubelogin/pkg/usecases/authentication/identifiers"
)

const TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange"

type Option struct {
	Resources              []string
	Audiences              []string
	RequestedTokenType     string
	SubjectToken           string
	SubjectTokenType       string
	BasicAuth              bool
	ActorToken             string            // optional
	ActorTokenType         string            // required iff ActorToken set
	AuthRequestExtraParams map[string]string // Optional to provided info like dex connector_id

}

type tokenExchangeOption struct {
	Resources              []string
	Audiences              []string
	RequestedTokenType     string
	SubjectToken           string
	SubjectTokenType       string
	BasicAuth              bool
	ActorToken             string            // optional
	ActorTokenType         string            // required iff ActorToken set
	AuthRequestExtraParams map[string]string // Optional to provided info like dex connector_id

	// accumulate validation errors
	errors   []error
	warnings []error
}

type tokenExchangeResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int64  `json:"expires_in"`
	Scope           string `json:"scope"`
	RefreshToken    string `json:"refresh_token"`

	// errors
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorURI         string `json:"error_uri"`
}

// TokenExchange provides the oauth2 token-exchange flow.
type TokenExchange struct {
	Logger logger.Interface
	// todo: expose http client
}

type tokenExchangeBuilder func(t tokenExchangeOption) tokenExchangeOption

func NewTokenExchangeOption(subjectToken, subjectTokenType string, options ...tokenExchangeBuilder) (*tokenExchangeOption, error) {

	t := tokenExchangeOption{
		Resources: []string{},
		Audiences: []string{},

		errors:   []error{},
		warnings: []error{},
	}

	if subjectToken == "" {
		t.errors = append(t.errors, fmt.Errorf("subject_token is required"))
	}

	canonical, err := identifiers.CanonicalTokenType(subjectTokenType)
	if err == nil {
		subjectTokenType = canonical
	} else {
		t.warnings = append(t.warnings, err)
	}

	t.SubjectToken = subjectToken
	t.SubjectTokenType = subjectTokenType

	for _, o := range options {
		t = o(t)
	}

	if len(t.errors) > 0 {
		// TODO: return contacted list of current errors to user with information
		// about current issues to fix
		err_msg := fmt.Sprintf("Token exchange errors: %d", len(t.errors))
		for _, e := range t.errors {
			err_msg += "\n" + e.Error()

		}
		return nil, fmt.Errorf(err_msg)
	}

	return &t, nil
}

// Support multiple "resource" parameters. Example in
// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-resource-indicators-08#section-2.1
func AddResource(resource string) tokenExchangeBuilder {
	return func(t tokenExchangeOption) tokenExchangeOption {

		// no-op
		if resource == "" {
			return t
		}

		failed := false
		u, err := url.Parse(resource)

		if err != nil {
			t.errors = append(t.errors, err)
			failed = true
		}

		// adhere to the rfc requirements
		if !u.IsAbs() {
			t.errors = append(t.errors, fmt.Errorf("resource uri must be absolute"))
			failed = true
		}

		if u.Fragment != "" {
			t.errors = append(t.errors, fmt.Errorf("resource uri must not include uri fragement"))
			failed = true
		}

		if !failed {
			t.Resources = append(t.Resources, resource)
		}
		return t
	}
}

// Support multiple "audience" parameters
func AddAudience(aud string) tokenExchangeBuilder {
	return func(t tokenExchangeOption) tokenExchangeOption {
		// no-op
		if aud == "" {
			return t
		}

		t.Audiences = append(t.Audiences, aud)
		return t
	}
}

// Support multiple "audience" parameters
func SetBasicAuth(useBasicAuth bool) tokenExchangeBuilder {
	return func(t tokenExchangeOption) tokenExchangeOption {
		t.BasicAuth = useBasicAuth
		return t
	}
}

func AddRequestedTokenType(tokenType string) tokenExchangeBuilder {
	return func(t tokenExchangeOption) tokenExchangeOption {

		// no-op
		if tokenType == "" {
			return t
		}

		canonical, err := identifiers.CanonicalTokenType(tokenType)

		// we don't *know* if this is an error. It's just probably an error.
		if err == nil {
			t.RequestedTokenType = canonical
		} else {
			// TODO: log a warning
			t.RequestedTokenType = tokenType
		}

		return t
	}
}

func AddActorToken(actorToken, actorTokenType string) tokenExchangeBuilder {
	return func(t tokenExchangeOption) tokenExchangeOption {

		// no-op
		if actorToken == "" {
			return t
		}

		canonical, err := identifiers.CanonicalTokenType(actorTokenType)

		// we don't *know* if this is an error. It's just probably an error.
		if err == nil {
			t.ActorTokenType = canonical
		} else {
			// TODO: log a warning
			t.ActorTokenType = actorTokenType
		}

		return t
	}
}

func AddExtraParams(params map[string]string) tokenExchangeBuilder {
	return func(t tokenExchangeOption) tokenExchangeOption {
		// no-op
		if t.AuthRequestExtraParams == nil {
			t.AuthRequestExtraParams = map[string]string{}
		}

		for k, v := range t.AuthRequestExtraParams {
			t.AuthRequestExtraParams[k] = v
		}

		return t
	}
}

func setupTokenExchangeOptions(o *Option) (t *tokenExchangeOption, err error) {
	t, err = NewTokenExchangeOption(
		o.SubjectToken,
		o.SubjectTokenType,
		AddRequestedTokenType(o.RequestedTokenType),
		SetBasicAuth(o.BasicAuth),
		AddActorToken(o.ActorToken, o.ActorTokenType),
		AddExtraParams(o.AuthRequestExtraParams),
	)

	for _, audience := range o.Audiences {
		AddAudience(audience)
	}
	for _, resource := range o.Resources {
		AddResource(resource)
	}

	return t, err

}

func (u *TokenExchange) Do(ctx context.Context, params *Option, oidcClient client.Interface, oidcProvider oidc.Provider) (*oidc.TokenSet, error) {
	// u.Logger.V(1).Infof("starting the oauth2 token-exchange flow")

	// u.Logger.V(1).Infof("starting the oauth2 token-exchange flow")
	tokenExchangeOpts, err := setupTokenExchangeOptions(params)

	if err != nil {
		return nil, err

	}

	for _, warn := range tokenExchangeOpts.warnings {
		fmt.Printf("[token-exchange] warning: %v", warn)
	}

	for _, err := range tokenExchangeOpts.errors {
		fmt.Printf("[token-exchange] error: %v", err)
	}
	if len(tokenExchangeOpts.errors) != 0 {
		return nil, tokenExchangeOpts.errors[0]
	}

	client := oidcClient.GetClient(ctx)

	ctx = gooidc.ClientContext(ctx, client)
	discovery, err := gooidc.NewProvider(ctx, oidcProvider.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("token-exchange error: %w", err)
	}

	data := url.Values{}
	data.Add("grant_type", TokenExchangeGrantType)
	for _, aud := range tokenExchangeOpts.Audiences {
		data.Add("audience", aud)
	}
	for _, resource := range tokenExchangeOpts.Resources {
		data.Add("resource", resource)
	}

	data.Add("scope", strings.Join(oidcProvider.ExtraScopes, " "))

	if tokenExchangeOpts.RequestedTokenType != "" {
		data.Add("requested_token_type", tokenExchangeOpts.RequestedTokenType)
	}

	fmt.Printf("env %s=%s\n", tokenExchangeOpts.SubjectToken, os.Getenv(tokenExchangeOpts.SubjectToken))
	if val := os.Getenv(tokenExchangeOpts.SubjectToken); val != "" {
		data.Add("subject_token", val)
	} else {
		data.Add("subject_token", tokenExchangeOpts.SubjectToken)
	}
	data.Add("subject_token_type", tokenExchangeOpts.SubjectTokenType)

	if tokenExchangeOpts.AuthRequestExtraParams != nil {
		for k, v := range tokenExchangeOpts.AuthRequestExtraParams {
			data.Add(k, v)
		}
	}

	if !tokenExchangeOpts.BasicAuth {
		data.Add("client_id", oidcProvider.ClientID)
		if oidcProvider.ClientSecret != "" {
			data.Add("client_secret", oidcProvider.ClientSecret)
		}
	}

	if tokenExchangeOpts.ActorToken != "" {
		if val := os.Getenv(tokenExchangeOpts.ActorToken); val != "" {
			data.Add("actor_token", val)
		} else {
			data.Add("actor_token", tokenExchangeOpts.ActorToken)
		}
		data.Add("actor_token_type", tokenExchangeOpts.ActorTokenType)
	}

	fmt.Println(data.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, discovery.Endpoint().TokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	if tokenExchangeOpts.BasicAuth {
		req.SetBasicAuth(oidcProvider.ClientID, oidcProvider.ClientSecret)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token-exchange error: %w", err)
	}
	defer resp.Body.Close()

	var respData tokenExchangeResponse
	err = json.NewDecoder(resp.Body).Decode(&respData)
	if err != nil {
		return nil, fmt.Errorf("token-exchange error: %w", err)
	}

	if respData.Error != "" {
		return nil, fmt.Errorf("token-exchange error: %s %s %s", respData.Error, respData.ErrorDescription, respData.ErrorURI)
	}

	// u.Logger.V(1).Infof("finished the oauth2 token-exchange flow")
	return &oidc.TokenSet{
		IDToken:      respData.AccessToken,
		RefreshToken: respData.RefreshToken,
	}, nil

}
