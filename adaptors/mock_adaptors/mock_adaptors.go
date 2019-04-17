// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/int128/kubelogin/adaptors/interfaces (interfaces: KubeConfig,HTTP,HTTPClientConfig,OIDC,Env,Logger)

// Package mock_adaptors is a generated GoMock package.
package mock_adaptors

import (
	context "context"
	tls "crypto/tls"
	go_oidc "github.com/coreos/go-oidc"
	gomock "github.com/golang/mock/gomock"
	interfaces "github.com/int128/kubelogin/adaptors/interfaces"
	api "k8s.io/client-go/tools/clientcmd/api"
	http "net/http"
	reflect "reflect"
)

// MockKubeConfig is a mock of KubeConfig interface
type MockKubeConfig struct {
	ctrl     *gomock.Controller
	recorder *MockKubeConfigMockRecorder
}

// MockKubeConfigMockRecorder is the mock recorder for MockKubeConfig
type MockKubeConfigMockRecorder struct {
	mock *MockKubeConfig
}

// NewMockKubeConfig creates a new mock instance
func NewMockKubeConfig(ctrl *gomock.Controller) *MockKubeConfig {
	mock := &MockKubeConfig{ctrl: ctrl}
	mock.recorder = &MockKubeConfigMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockKubeConfig) EXPECT() *MockKubeConfigMockRecorder {
	return m.recorder
}

// LoadFromFile mocks base method
func (m *MockKubeConfig) LoadFromFile(arg0 string) (*api.Config, error) {
	ret := m.ctrl.Call(m, "LoadFromFile", arg0)
	ret0, _ := ret[0].(*api.Config)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// LoadFromFile indicates an expected call of LoadFromFile
func (mr *MockKubeConfigMockRecorder) LoadFromFile(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "LoadFromFile", reflect.TypeOf((*MockKubeConfig)(nil).LoadFromFile), arg0)
}

// WriteToFile mocks base method
func (m *MockKubeConfig) WriteToFile(arg0 *api.Config, arg1 string) error {
	ret := m.ctrl.Call(m, "WriteToFile", arg0, arg1)
	ret0, _ := ret[0].(error)
	return ret0
}

// WriteToFile indicates an expected call of WriteToFile
func (mr *MockKubeConfigMockRecorder) WriteToFile(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "WriteToFile", reflect.TypeOf((*MockKubeConfig)(nil).WriteToFile), arg0, arg1)
}

// MockHTTP is a mock of HTTP interface
type MockHTTP struct {
	ctrl     *gomock.Controller
	recorder *MockHTTPMockRecorder
}

// MockHTTPMockRecorder is the mock recorder for MockHTTP
type MockHTTPMockRecorder struct {
	mock *MockHTTP
}

// NewMockHTTP creates a new mock instance
func NewMockHTTP(ctrl *gomock.Controller) *MockHTTP {
	mock := &MockHTTP{ctrl: ctrl}
	mock.recorder = &MockHTTPMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockHTTP) EXPECT() *MockHTTPMockRecorder {
	return m.recorder
}

// NewClient mocks base method
func (m *MockHTTP) NewClient(arg0 interfaces.HTTPClientConfig) (*http.Client, error) {
	ret := m.ctrl.Call(m, "NewClient", arg0)
	ret0, _ := ret[0].(*http.Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewClient indicates an expected call of NewClient
func (mr *MockHTTPMockRecorder) NewClient(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewClient", reflect.TypeOf((*MockHTTP)(nil).NewClient), arg0)
}

// NewClientConfig mocks base method
func (m *MockHTTP) NewClientConfig() interfaces.HTTPClientConfig {
	ret := m.ctrl.Call(m, "NewClientConfig")
	ret0, _ := ret[0].(interfaces.HTTPClientConfig)
	return ret0
}

// NewClientConfig indicates an expected call of NewClientConfig
func (mr *MockHTTPMockRecorder) NewClientConfig() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewClientConfig", reflect.TypeOf((*MockHTTP)(nil).NewClientConfig))
}

// MockHTTPClientConfig is a mock of HTTPClientConfig interface
type MockHTTPClientConfig struct {
	ctrl     *gomock.Controller
	recorder *MockHTTPClientConfigMockRecorder
}

// MockHTTPClientConfigMockRecorder is the mock recorder for MockHTTPClientConfig
type MockHTTPClientConfigMockRecorder struct {
	mock *MockHTTPClientConfig
}

// NewMockHTTPClientConfig creates a new mock instance
func NewMockHTTPClientConfig(ctrl *gomock.Controller) *MockHTTPClientConfig {
	mock := &MockHTTPClientConfig{ctrl: ctrl}
	mock.recorder = &MockHTTPClientConfigMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockHTTPClientConfig) EXPECT() *MockHTTPClientConfigMockRecorder {
	return m.recorder
}

// AddCertificateFromFile mocks base method
func (m *MockHTTPClientConfig) AddCertificateFromFile(arg0 string) error {
	ret := m.ctrl.Call(m, "AddCertificateFromFile", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddCertificateFromFile indicates an expected call of AddCertificateFromFile
func (mr *MockHTTPClientConfigMockRecorder) AddCertificateFromFile(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddCertificateFromFile", reflect.TypeOf((*MockHTTPClientConfig)(nil).AddCertificateFromFile), arg0)
}

// AddEncodedCertificate mocks base method
func (m *MockHTTPClientConfig) AddEncodedCertificate(arg0 string) error {
	ret := m.ctrl.Call(m, "AddEncodedCertificate", arg0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddEncodedCertificate indicates an expected call of AddEncodedCertificate
func (mr *MockHTTPClientConfigMockRecorder) AddEncodedCertificate(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AddEncodedCertificate", reflect.TypeOf((*MockHTTPClientConfig)(nil).AddEncodedCertificate), arg0)
}

// SetSkipTLSVerify mocks base method
func (m *MockHTTPClientConfig) SetSkipTLSVerify(arg0 bool) {
	m.ctrl.Call(m, "SetSkipTLSVerify", arg0)
}

// SetSkipTLSVerify indicates an expected call of SetSkipTLSVerify
func (mr *MockHTTPClientConfigMockRecorder) SetSkipTLSVerify(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetSkipTLSVerify", reflect.TypeOf((*MockHTTPClientConfig)(nil).SetSkipTLSVerify), arg0)
}

// TLSConfig mocks base method
func (m *MockHTTPClientConfig) TLSConfig() *tls.Config {
	ret := m.ctrl.Call(m, "TLSConfig")
	ret0, _ := ret[0].(*tls.Config)
	return ret0
}

// TLSConfig indicates an expected call of TLSConfig
func (mr *MockHTTPClientConfigMockRecorder) TLSConfig() *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "TLSConfig", reflect.TypeOf((*MockHTTPClientConfig)(nil).TLSConfig))
}

// MockOIDC is a mock of OIDC interface
type MockOIDC struct {
	ctrl     *gomock.Controller
	recorder *MockOIDCMockRecorder
}

// MockOIDCMockRecorder is the mock recorder for MockOIDC
type MockOIDCMockRecorder struct {
	mock *MockOIDC
}

// NewMockOIDC creates a new mock instance
func NewMockOIDC(ctrl *gomock.Controller) *MockOIDC {
	mock := &MockOIDC{ctrl: ctrl}
	mock.recorder = &MockOIDCMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockOIDC) EXPECT() *MockOIDCMockRecorder {
	return m.recorder
}

// Authenticate mocks base method
func (m *MockOIDC) Authenticate(arg0 context.Context, arg1 interfaces.OIDCAuthenticateIn, arg2 interfaces.OIDCAuthenticateCallback) (*interfaces.OIDCAuthenticateOut, error) {
	ret := m.ctrl.Call(m, "Authenticate", arg0, arg1, arg2)
	ret0, _ := ret[0].(*interfaces.OIDCAuthenticateOut)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Authenticate indicates an expected call of Authenticate
func (mr *MockOIDCMockRecorder) Authenticate(arg0, arg1, arg2 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Authenticate", reflect.TypeOf((*MockOIDC)(nil).Authenticate), arg0, arg1, arg2)
}

// VerifyIDToken mocks base method
func (m *MockOIDC) VerifyIDToken(arg0 context.Context, arg1 interfaces.OIDCVerifyTokenIn) (*go_oidc.IDToken, error) {
	ret := m.ctrl.Call(m, "VerifyIDToken", arg0, arg1)
	ret0, _ := ret[0].(*go_oidc.IDToken)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VerifyIDToken indicates an expected call of VerifyIDToken
func (mr *MockOIDCMockRecorder) VerifyIDToken(arg0, arg1 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VerifyIDToken", reflect.TypeOf((*MockOIDC)(nil).VerifyIDToken), arg0, arg1)
}

// MockEnv is a mock of Env interface
type MockEnv struct {
	ctrl     *gomock.Controller
	recorder *MockEnvMockRecorder
}

// MockEnvMockRecorder is the mock recorder for MockEnv
type MockEnvMockRecorder struct {
	mock *MockEnv
}

// NewMockEnv creates a new mock instance
func NewMockEnv(ctrl *gomock.Controller) *MockEnv {
	mock := &MockEnv{ctrl: ctrl}
	mock.recorder = &MockEnvMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockEnv) EXPECT() *MockEnvMockRecorder {
	return m.recorder
}

// Getenv mocks base method
func (m *MockEnv) Getenv(arg0 string) string {
	ret := m.ctrl.Call(m, "Getenv", arg0)
	ret0, _ := ret[0].(string)
	return ret0
}

// Getenv indicates an expected call of Getenv
func (mr *MockEnvMockRecorder) Getenv(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Getenv", reflect.TypeOf((*MockEnv)(nil).Getenv), arg0)
}

// MockLogger is a mock of Logger interface
type MockLogger struct {
	ctrl     *gomock.Controller
	recorder *MockLoggerMockRecorder
}

// MockLoggerMockRecorder is the mock recorder for MockLogger
type MockLoggerMockRecorder struct {
	mock *MockLogger
}

// NewMockLogger creates a new mock instance
func NewMockLogger(ctrl *gomock.Controller) *MockLogger {
	mock := &MockLogger{ctrl: ctrl}
	mock.recorder = &MockLoggerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockLogger) EXPECT() *MockLoggerMockRecorder {
	return m.recorder
}

// Debugf mocks base method
func (m *MockLogger) Debugf(arg0 interfaces.LogLevel, arg1 string, arg2 ...interface{}) {
	varargs := []interface{}{arg0, arg1}
	for _, a := range arg2 {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Debugf", varargs...)
}

// Debugf indicates an expected call of Debugf
func (mr *MockLoggerMockRecorder) Debugf(arg0, arg1 interface{}, arg2 ...interface{}) *gomock.Call {
	varargs := append([]interface{}{arg0, arg1}, arg2...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Debugf", reflect.TypeOf((*MockLogger)(nil).Debugf), varargs...)
}

// IsEnabled mocks base method
func (m *MockLogger) IsEnabled(arg0 interfaces.LogLevel) bool {
	ret := m.ctrl.Call(m, "IsEnabled", arg0)
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsEnabled indicates an expected call of IsEnabled
func (mr *MockLoggerMockRecorder) IsEnabled(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "IsEnabled", reflect.TypeOf((*MockLogger)(nil).IsEnabled), arg0)
}

// Printf mocks base method
func (m *MockLogger) Printf(arg0 string, arg1 ...interface{}) {
	varargs := []interface{}{arg0}
	for _, a := range arg1 {
		varargs = append(varargs, a)
	}
	m.ctrl.Call(m, "Printf", varargs...)
}

// Printf indicates an expected call of Printf
func (mr *MockLoggerMockRecorder) Printf(arg0 interface{}, arg1 ...interface{}) *gomock.Call {
	varargs := append([]interface{}{arg0}, arg1...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Printf", reflect.TypeOf((*MockLogger)(nil).Printf), varargs...)
}

// SetLevel mocks base method
func (m *MockLogger) SetLevel(arg0 interfaces.LogLevel) {
	m.ctrl.Call(m, "SetLevel", arg0)
}

// SetLevel indicates an expected call of SetLevel
func (mr *MockLoggerMockRecorder) SetLevel(arg0 interface{}) *gomock.Call {
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "SetLevel", reflect.TypeOf((*MockLogger)(nil).SetLevel), arg0)
}
