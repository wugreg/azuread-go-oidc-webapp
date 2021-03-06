package main

import (
	"encoding/base32"
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
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

const (
	SERVER_PORT            = 9090
	PAGE_PATH              = "pages"
	SESSION_STORE_NAME     = "go-msid-secret"
	SESSION_NAME           = "msid"
	PRINCIPAL_SESSION_NAME = "principal"
	STATE                  = "state"
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

type AccessToken struct {
	Value string
}

var appConfig AppConfig
var sessionStore = sessions.NewCookieStore([]byte(SESSION_STORE_NAME))
var tokenResponseMap map[string]*TokenResponse

func init() {
	data, err := ioutil.ReadFile("./conf/aad.json")
	if err != nil {
		fmt.Println("Can not find aad.json")
		panic(err)
	} else {
		json.Unmarshal(data, &appConfig)
	}

	tokenResponseMap = make(map[string]*TokenResponse)

	sessionManager = make(map[string]map[string]interface{})
}

func main() {
	fmt.Println("Hello, Azure")

	startServer()
}

func startServer() {
	fmt.Println("Starting Web server")

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
		fmt.Println("/")
		if doHttpSession(w, r) == "" {
			http.Error(w, "Could not process HTTP session", http.StatusInternalServerError)
			return
		}
		http.ServeFile(w, r, fmt.Sprintf("%v/%v", PAGE_PATH, "index.html"))
	})

	router.HandleFunc("/secure/aad", func(w http.ResponseWriter, r *http.Request) {
		if doHttpSession(w, r) == "" {
			http.Error(w, "Could not process HTTP session", http.StatusInternalServerError)
			return
		}

		if containsAuthenticationCode(r) {
			currentUri := r.URL.Path
			fullUrl := r.URL.RequestURI()

			processAuthenticationCodeRedirect(w, r, currentUri, fullUrl)
			return
		}

		if !isAuthenticated(w, r) {
			// Forward to Azure AD authorize endpoint
			sendAuthRedirect(w, r)
			return
		}

		//fmt.Println("Authenticated")
		http.ServeFile(w, r, fmt.Sprintf("./%v/%v", PAGE_PATH, "secure.html"))
	})

	router.HandleFunc("/graph/me", func(w http.ResponseWriter, r *http.Request) {
		if doHttpSession(w, r) == "" {
			http.Error(w, "Could not process HTTP session", http.StatusInternalServerError)
			return
		}

		me := callGraph(r)

		if me == nil {
			u := User{
				DisplayName:       "unknown",
				UserPrincipalName: "unknown",
			}
			me = &GraphMeResponse{User: u}
		}

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
	state := getFromResponse(r.URL.Query(), STATE)
	if state == "" {
		http.Error(w, "Could not validate state", http.StatusInternalServerError)
		return
	}

	stateData := validateState(r, state)
	if stateData == nil {
		http.Error(w, "Could not validate state", http.StatusInternalServerError)
		return
	}

	oidcResponse := parseAuthResponse(r)
	if !isValiduthRespMatchesAuthCodeFlow(oidcResponse) {
		fmt.Println(FAILED_TO_VALIDATE_MESSAGE + "unexpected set of artifacts received")
		http.Error(w, FAILED_TO_VALIDATE_MESSAGE+"unexpected set of artifacts received", http.StatusInternalServerError)
		return
	}

	// Call AAD to get accessToken with code
	tokenResponse := getAuthResultByAuthCode(oidcResponse.authCode)
	if tokenResponse != nil {
		setSessionPrincipal(w, r, tokenResponse)

		http.ServeFile(w, r, fmt.Sprintf("%v/%v", PAGE_PATH, "secure.html"))
		return
	}

	http.ServeFile(w, r, fmt.Sprintf("%v/%v", PAGE_PATH, "index.html"))
}

func validateState(r *http.Request, state string) *StateData {
	return removeStateFromSession(r, state)
}

func removeStateFromSession(r *http.Request, state string) *StateData {
	sessionID := getSessionID(r)
	states, _ := sessionManager[sessionID][STATES].(map[string]*StateData)
	if states != nil {
		eliminateExpiredStates(states)
		stateData := states[state]
		if stateData != nil {
			delete(states, state)
			return stateData
		}
	}
	return nil
}

func eliminateExpiredStates(states map[string]*StateData) {
	//TODO
}

func callGraph(r *http.Request) *GraphMeResponse {
	sessionID := getSessionID(r)
	tokenResponse := tokenResponseMap[sessionID]
	if tokenResponse != nil {
		endpoint := appConfig.MsGraphEndpointHost + "/me"

		headers := make(map[string]string)
		headers["Content-Type"] = "application/json"
		headers["Authorization"] = "Bearer " + tokenResponse.AccessToken

		var me GraphMeResponse
		json.Unmarshal(doRequest(nil, endpoint, "GET", headers), &me)
		return &me
	}

	fmt.Println("No access token, probably not authorized")
	return nil
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
	sessionID := getSessionID(r)

	sessionData := sessionManager[sessionID]
	if sessionData == nil {
		sessionData = make(map[string]interface{})
	}

	states, _ := sessionData[STATES].(map[string]*StateData)
	if states == nil {
		states = make(map[string]*StateData)
	}
	states[state] = &StateData{
		Nonce:          nonce,
		ExpirationDate: time.Now(),
	}

	saveToSession(sessionID, STATES, states)
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
	sessionID := getSessionID(r)

	if sessionID != "" {
		return tokenResponseMap[sessionID] != nil
	}

	return false
}

func setSessionPrincipal(w http.ResponseWriter, r *http.Request, tokenResponse *TokenResponse) {
	session, err := sessionStore.Get(r, SESSION_NAME)
	if err != nil {
		fmt.Println(err)
		panic("Failed to get session")
	}

	if session.ID == "" {
		// Generate a random session ID key suitable for storage in the DB
		session.ID = string(securecookie.GenerateRandomKey(32))
		session.ID = strings.TrimRight(base32.StdEncoding.EncodeToString(securecookie.GenerateRandomKey(32)), "=")
	}
	tokenResponseMap[session.ID] = tokenResponse

	session.Values[PRINCIPAL_SESSION_NAME] = session.ID
	if err = session.Save(r, w); err != nil {
		fmt.Println(err)
	}
}
