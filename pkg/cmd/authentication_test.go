package cmd

import (
	"github.com/int128/kubelogin/pkg/usecases/authentication/tokenexchange"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/int128/kubelogin/pkg/usecases/authentication"
	"github.com/int128/kubelogin/pkg/usecases/authentication/authcode"
	"github.com/int128/kubelogin/pkg/usecases/authentication/ropc"
	"github.com/spf13/pflag"
)

func Test_authenticationOptions_grantOptionSet(t *testing.T) {
	tests := map[string]struct {
		args []string
		want authentication.GrantOptionSet
	}{
		"NoFlag": {
			want: authentication.GrantOptionSet{
				AuthCodeBrowserOption: &authcode.BrowserOption{
					BindAddress:           defaultListenAddress,
					AuthenticationTimeout: defaultAuthenticationTimeoutSec * time.Second,
					RedirectURLHostname:   "localhost",
				},
			},
		},
		"FullOptions": {
			args: []string{
				"--grant-type", "authcode",
				"--listen-address", "127.0.0.1:10080",
				"--listen-address", "127.0.0.1:20080",
				"--skip-open-browser",
				"--browser-command", "firefox",
				"--authentication-timeout-sec", "10",
				"--local-server-cert", "/path/to/local-server-cert",
				"--local-server-key", "/path/to/local-server-key",
				"--open-url-after-authentication", "https://example.com/success.html",
				"--oidc-redirect-url-hostname", "example",
				"--oidc-auth-request-extra-params", "ttl=86400",
				"--oidc-auth-request-extra-params", "reauth=true",
				"--username", "USER",
				"--password", "PASS",
			},
			want: authentication.GrantOptionSet{
				AuthCodeBrowserOption: &authcode.BrowserOption{
					BindAddress:                []string{"127.0.0.1:10080", "127.0.0.1:20080"},
					SkipOpenBrowser:            true,
					BrowserCommand:             "firefox",
					AuthenticationTimeout:      10 * time.Second,
					LocalServerCertFile:        "/path/to/local-server-cert",
					LocalServerKeyFile:         "/path/to/local-server-key",
					OpenURLAfterAuthentication: "https://example.com/success.html",
					RedirectURLHostname:        "example",
					AuthRequestExtraParams:     map[string]string{"ttl": "86400", "reauth": "true"},
				},
			},
		},
		"when --listen-port is set, it should convert the port to address": {
			args: []string{
				"--listen-port", "10080",
				"--listen-port", "20080",
			},
			want: authentication.GrantOptionSet{
				AuthCodeBrowserOption: &authcode.BrowserOption{
					BindAddress:           []string{"127.0.0.1:10080", "127.0.0.1:20080"},
					AuthenticationTimeout: defaultAuthenticationTimeoutSec * time.Second,
					RedirectURLHostname:   "localhost",
				},
			},
		},
		"when --listen-port is set, it should ignore --listen-address flags": {
			args: []string{
				"--listen-port", "10080",
				"--listen-port", "20080",
				"--listen-address", "127.0.0.1:30080",
				"--listen-address", "127.0.0.1:40080",
			},
			want: authentication.GrantOptionSet{
				AuthCodeBrowserOption: &authcode.BrowserOption{
					BindAddress:           []string{"127.0.0.1:10080", "127.0.0.1:20080"},
					AuthenticationTimeout: defaultAuthenticationTimeoutSec * time.Second,
					RedirectURLHostname:   "localhost",
				},
			},
		},
		"GrantType=authcode-keyboard": {
			args: []string{
				"--grant-type", "authcode-keyboard",
			},
			want: authentication.GrantOptionSet{
				AuthCodeKeyboardOption: &authcode.KeyboardOption{
					RedirectURL: oobRedirectURI,
				},
			},
		},
		"GrantType=authcode-keyboard with full options": {
			args: []string{
				"--grant-type", "authcode-keyboard",
				"--oidc-redirect-url-authcode-keyboard", "http://localhost",
			},
			want: authentication.GrantOptionSet{
				AuthCodeKeyboardOption: &authcode.KeyboardOption{
					RedirectURL: "http://localhost",
				},
			},
		},
		"GrantType=password": {
			args: []string{
				"--grant-type", "password",
				"--listen-address", "127.0.0.1:10080",
				"--listen-address", "127.0.0.1:20080",
				"--username", "USER",
				"--password", "PASS",
			},
			want: authentication.GrantOptionSet{
				ROPCOption: &ropc.Option{
					Username: "USER",
					Password: "PASS",
				},
			},
		},
		"GrantType=auto": {
			args: []string{
				"--listen-address", "127.0.0.1:10080",
				"--listen-address", "127.0.0.1:20080",
				"--username", "USER",
				"--password", "PASS",
			},
			want: authentication.GrantOptionSet{
				ROPCOption: &ropc.Option{
					Username: "USER",
					Password: "PASS",
				},
			},
		},
		"GrantType=token-exchange": {
			args: []string{
				"--grant-type", "token-exchange",
				"--token-exchange-resource", "https://resource.example.com",
				"--token-exchange-audience", "aud",
				"--token-exchange-subject-token", "sub",
				"--token-exchange-subject-token-type", "sub-type",
				"--token-exchange-requested-token-type", "sub",
				"--token-exchange-actor-token", "act",
				"--token-exchange-actor-token-type", "act",
			},
			want: authentication.GrantOptionSet{
				TokenExchangeOption: &tokenexchange.Option{
					Resources:          []string{"https://resource.example.com"},
					Audiences:          []string{"aud"},
					SubjectToken:       "sub",
					SubjectTokenType:   "sub-type",
					RequestedTokenType: "sub",
					ActorToken:         "act",
					ActorTokenType:     "act",
				},
			},
		},
		"GrantType=token-exchange: multiple audiences": {
			args: []string{
				"--grant-type", "token-exchange",
				"--token-exchange-resource", "https://foo.example.com",
				"--token-exchange-resource", "https://bar.example.com",
				"--token-exchange-audience", "foo",
				"--token-exchange-audience", "bar",
				"--token-exchange-subject-token", "sub",
				"--token-exchange-subject-token-type", "sub-type",
				"--token-exchange-requested-token-type", "req-type",
				"--token-exchange-actor-token", "act",
				"--token-exchange-actor-token-type", "act-type",
			},
			want: authentication.GrantOptionSet{
				TokenExchangeOption: &tokenexchange.Option{
					Resources: []string{
						"https://foo.example.com",
						"https://bar.example.com"},
					Audiences:          []string{"foo", "bar"},
					SubjectToken:       "sub",
					SubjectTokenType:   "sub-type",
					RequestedTokenType: "req-type",
					ActorToken:         "act",
					ActorTokenType:     "act-type",
				},
			},
		},
	}

	for name, c := range tests {
		t.Run(name, func(t *testing.T) {
			var o authenticationOptions
			f := pflag.NewFlagSet("", pflag.ContinueOnError)
			o.addFlags(f)
			if err := f.Parse(c.args); err != nil {
				t.Fatalf("Parse error: %s", err)
			}
			got, err := o.grantOptionSet()
			if err != nil {
				t.Fatalf("grantOptionSet error: %s", err)
			}
			if diff := cmp.Diff(c.want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
