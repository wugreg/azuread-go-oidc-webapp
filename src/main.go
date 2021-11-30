package main

import (
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
)

const (
	SERVER_PORT            = 9090
	PAGE_PATH              = "pages"
	SESSION_STORE_NAME     = "go-msid-secret"
	SESSION_NAME           = "msid"
	PRINCIPAL_SESSION_NAME = "principal"
	STATES                 = "states"
	DEFAULT_SCOPE          = "user.read"

	FAILED_TO_VALIDATE_MESSAGE = "Failed to validate data received from Authorization service - "
)

type AppConfig struct {
	ClientId            string `json:"clientId"`
	Authority           string `json:"authority"`
	SecretKey           string `json:"secretKey"`
	RedirectUriSignin   string `json:"redirectUriSignin"`
	RedirectUriGraph    string `json:"redirectUriGraph"`
	MsGraphEndpointHost string `json:"msGraphEndpointHost"`
	Scope               string `json:"scope"`
}

type StateData struct {
	Nonce          string
	ExpirationDate time.Time
}

type StateDataMap struct {
	DataMap map[string]StateData
}

type AuthorizationResponse struct {
	authCode    string
	state       string
	sessionData string
	accessToken string
	idToken     string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refreshToken"`
	IdToken      string `json:"id_token"`
}

type User struct {
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
}

type GraphMeResponse struct {
	User
	GivenName string `json:"givenName"`
	SurName   string `json:"surname"`
	ID        string `json:"id"`
}

var appConfig AppConfig
var sessionStore = sessions.NewCookieStore([]byte(SESSION_STORE_NAME))
var accessToken string
var me GraphMeResponse

func init() {
	data, err := ioutil.ReadFile("./conf/aad.json")
	if err != nil {
		fmt.Println("Can not find aad.json")
		panic(err)
	} else {
		json.Unmarshal(data, &appConfig)
	}

	gob.Register(StateDataMap{})
	gob.Register(TokenResponse{})
}

func main() {
	fmt.Println("Hello, Microsoft")

	startServer()
}

func startServer() {
	fmt.Println("Starting web server")

	r := mux.NewRouter()
	routes(r)

	fmt.Printf("Listening on port %d\n", SERVER_PORT)
	if err := http.ListenAndServe(fmt.Sprintf(":%v", SERVER_PORT), r); err != nil {
		fmt.Println(err.Error())
		panic(err)
	}

	time.Sleep(300 * time.Millisecond)
}

func routes(router *mux.Router) {
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, fmt.Sprintf("%v/%v", PAGE_PATH, "index.html"))
	})

	router.HandleFunc("/secure/aad", func(w http.ResponseWriter, r *http.Request) {
		if containsAuthenticationCode(r) {
			currentUri := r.URL.Path
			fullUrl := r.URL.RequestURI()

			processAuthenticationCodeRedirect(w, r, currentUri, fullUrl)
			return
		}

		if !isAuthenticated(w, r) {
			// Forward to Azure AD for authorize endpoint
			sendAuthRedirect(w, r)
		}

		http.ServeFile(w, r, fmt.Sprintf("./%v/%v", PAGE_PATH, "index.html"))
	})

	router.HandleFunc("/graph/me", func(w http.ResponseWriter, r *http.Request) {
		callGraph(accessToken)

		keywordTemplate := template.Must(template.ParseFiles(fmt.Sprintf("./%v/%v", PAGE_PATH, "graph.html")))
		err := keywordTemplate.Execute(w, me.User)
		if err != nil {
			fmt.Println(err.Error())
		}
	})
}

func containsAuthenticationCode(r *http.Request) bool {
	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			fmt.Println(err.Error())
		} else {
			for key, _ := range r.PostForm {
				if key == "error" {
					return true
				}
			}
		}
	}

	_, containIdToken := r.URL.Query()["id_token"]
	_, containsAuthCode := r.URL.Query()["code"]

	return containsAuthCode || containIdToken
}

func processAuthenticationCodeRedirect(w http.ResponseWriter, r *http.Request, currentUri string, fullUrl string) {
	oidcResponse := parseAuthResponse(r)
	if !isValiduthRespMatchesAuthCodeFlow(oidcResponse) {
		fmt.Println(FAILED_TO_VALIDATE_MESSAGE + "unexpected set of artifacts received")
		http.Error(w, FAILED_TO_VALIDATE_MESSAGE+"unexpected set of artifacts received", http.StatusInternalServerError)
		return
	}

	// Call AAD to get accessToken with code
	tokenResponse := getAuthResultByAuthCode(oidcResponse.authCode)
	if tokenResponse != nil {
		accessToken = tokenResponse.AccessToken
		setSessionPrincipal(w, r, accessToken)

		http.ServeFile(w, r, fmt.Sprintf("%v/%v", PAGE_PATH, "secure.html"))
		return
	}

	http.ServeFile(w, r, fmt.Sprintf("%v/%v", PAGE_PATH, "index.html"))
}

func callGraph(accessToken string) {
	endpoint := appConfig.MsGraphEndpointHost + "/me"

	headers := make(map[string]string)
	headers["Content-Type"] = "application/json"
	headers["Authorization"] = "Bearer " + accessToken

	json.Unmarshal(doRequest(nil, endpoint, "GET", headers), &me)
}

func getAuthResultByAuthCode(authCode string) *TokenResponse {
	scope := DEFAULT_SCOPE
	if appConfig.Scope != "" {
		scope = appConfig.Scope
	}

	data := url.Values{}
	data.Set("client_id", appConfig.ClientId)
	data.Set("scope", scope)
	data.Set("code", authCode)
	data.Set("redirect_uri", appConfig.RedirectUriSignin)
	data.Set("grant_type", "authorization_code")
	data.Set("client_secret", appConfig.SecretKey)

	endpoint := appConfig.Authority + "/oauth2/v2.0/token"

	headers := make(map[string]string)
	headers["Content-Type"] = "application/x-www-form-urlencoded"
	headers["Content-Length"] = strconv.Itoa(len(data.Encode()))

	body := doRequest(data, endpoint, "POST", headers)

	var tokenResponse TokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		fmt.Println(err)
		return nil
	}

	return &tokenResponse
}

func doRequest(data url.Values, endpoint string, method string, headers map[string]string) []byte {
	u, _ := url.ParseRequestURI(endpoint)
	urlStr := u.String()

	var r io.Reader
	if data != nil {
		r = strings.NewReader(data.Encode())
	}
	req, err := http.NewRequest(method, urlStr, r)
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	for k, v := range headers {
		req.Header.Add(k, v)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	if resp.StatusCode != 200 {
		fmt.Printf("Error code: %v", resp.StatusCode)
		return nil
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err.Error())
		return nil
	}

	return body
}

func isValiduthRespMatchesAuthCodeFlow(authResponse AuthorizationResponse) bool {
	return authResponse.idToken == "" && authResponse.accessToken == "" && authResponse.authCode != ""
}

func parseAuthResponse(r *http.Request) AuthorizationResponse {
	val := r.URL.Query()

	return AuthorizationResponse{
		state:       getFromResponse(val, "state"),
		authCode:    getFromResponse(val, "code"),
		sessionData: getFromResponse(val, "sessionData"),
		idToken:     getFromResponse(val, "id_token"),
		accessToken: getFromResponse(val, "accessToken"),
	}
}

func getFromResponse(val url.Values, name string) string {
	values := val[name]
	if len(values) > 0 {
		return values[0]
	}
	return ""
}

func sendAuthRedirect(w http.ResponseWriter, r *http.Request) {
	// state parameter to validate response from Authorization server and nonce parameter to validate idToken
	state := uuid.New().String()
	nonce := uuid.New().String()

	storeStateAndNonceInSession(w, r, state, nonce)

	claim := ""
	claims := r.URL.Query()["claims"]
	if len(claims) > 0 {
		claim = claims[0]
	}

	http.Redirect(w, r, getAuthorizationCodeUrl(claim, state, nonce), http.StatusFound)
}

func storeStateAndNonceInSession(w http.ResponseWriter, r *http.Request, state string, nonce string) {
	session, err := sessionStore.Get(r, SESSION_NAME)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var stateDataMap StateDataMap
	var ok bool

	val := session.Values[STATES]
	if stateDataMap, ok = val.(StateDataMap); !ok {
		stateDataMap = StateDataMap{
			DataMap: make(map[string]StateData),
		}
	}

	stateDataMap.DataMap[state] = StateData{
		Nonce:          nonce,
		ExpirationDate: time.Now(),
	}

	session.Values[STATES] = stateDataMap
	if err = session.Save(r, w); err != nil {
		fmt.Println(err)
	}
}

func getAuthorizationCodeUrl(claims string, state string, nonce string) string {
	scope := DEFAULT_SCOPE
	if appConfig.Scope != "" {
		scope = appConfig.Scope
	}

	return fmt.Sprintf(`%v/oauth2/v2.0/authorize?client_id=%v&response_type=code&redirect_uri=%v&response_mode=query&scope=%v&state=%v`,
		appConfig.Authority,
		appConfig.ClientId,
		appConfig.RedirectUriSignin,
		scope,
		state)
}

func isAuthenticated(w http.ResponseWriter, r *http.Request) bool {
	session, err := sessionStore.Get(r, SESSION_NAME)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return false
	}

	return session.Values[PRINCIPAL_SESSION_NAME] != nil
}

func setSessionPrincipal(w http.ResponseWriter, r *http.Request, accessToken string /*tokenResponse *TokenResponse*/) {
	session, err := sessionStore.Get(r, SESSION_NAME)
	if err != nil {
		fmt.Println(err)
	}

	session.Values[PRINCIPAL_SESSION_NAME] = accessToken /*tokenResponse*/
	if err = session.Save(r, w); err != nil {
		fmt.Println(err)
	}
}
