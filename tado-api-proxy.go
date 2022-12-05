package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type environment struct {
	apiPort      string
	clientSecret string
	debug        bool
	password     string
	username     string
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	Jti          string `json:"jti"`
}

const (
	clientSecret           = "wZaRN7rpjn3FoNyF5IFuxg9uMzYJcvOoQ8QWiIqS3hfk6gLhVlG57j5YNoZL2Rtc"
	tokenUrl               = "https://auth.tado.com/oauth/token"
	meUrl                  = "https://my.tado.com/api/v1/me"
	homesUrl               = "https://my.tado.com/api/v2/homes/<homeId>"
	zonesUrl               = "https://my.tado.com/api/v2/homes/<homeId>/zones"
	zonesStateUrl          = "https://my.tado.com/api/v2/homes/<homeId>/zones/<zone>/state"
	zoneStateDateReportUrl = "https://my.tado.com/api/v2/homes/<homeId>/zones/<zone>/dayReport?date=<date>"
	weatherUrl             = "https://my.tado.com/api/v2/homes/<homeId>/weather"
)

var (
	env   environment
	token TokenResponse
)

func main() {

	initApp()

	go func() {
		for {
			refreshToken()
			time.Sleep(time.Duration(token.ExpiresIn-10) * time.Second)
		}
	}()

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/me", getMe)
	router.HandleFunc("/home", getHome)
	router.HandleFunc("/weather", getWeather)
	router.HandleFunc("/zones", getZones)
	router.HandleFunc("/zoneState", getZoneState)
	router.HandleFunc("/zoneStateDateReport", getZoneStateDayReport)

	router.Use(loggingMiddleware)
	http.Handle("/", router)
	log.Info().Msg("Get current state on http://<your hostname>:" + env.apiPort + "/state")
	log.Fatal().Err(http.ListenAndServe(":"+env.apiPort, nil))

}

func requestTado(tadoUrl string, responseWriter http.ResponseWriter) {

	log.Debug().Msg("requestTado")

	//	responseWriter.WriteHeader(http.StatusCreated)

	log.Debug().Msg(token.AccessToken)

	client := &http.Client{}
	req, _ := http.NewRequest("GET", tadoUrl, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token.AccessToken)
	resp, _ := client.Do(req)

	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	fmt.Println(string(respBody))

	if resp.StatusCode == http.StatusOK {
		responseWriter.Write(respBody)
		responseWriter.WriteHeader(http.StatusOK)
	} else {
		responseWriter.WriteHeader(http.StatusInternalServerError)
		log.Debug().Str("request", req.URL.String()).Msg("The request failed.")
		log.Fatal().Str("http-state", resp.Status).Msg("Request failed with error.")
	}

}

func getHome(responseWriter http.ResponseWriter, request *http.Request) {

	log.Debug().Msg("getHome")

	homeId := request.URL.Query().Get("homeId")
	tadoUrl := strings.Replace(homesUrl, "<homeId>", homeId, 1)
	requestTado(tadoUrl, responseWriter)

}

func getZones(responseWriter http.ResponseWriter, request *http.Request) {

	log.Debug().Msg("getZones")

	homeId := request.URL.Query().Get("homeId")
	tadoUrl := strings.Replace(zonesUrl, "<homeId>", homeId, 1)
	requestTado(tadoUrl, responseWriter)

}

func getWeather(responseWriter http.ResponseWriter, request *http.Request) {

	log.Debug().Msg("getWeather")

	homeId := request.URL.Query().Get("homeId")
	tadoUrl := strings.Replace(weatherUrl, "<homeId>", homeId, 1)
	requestTado(tadoUrl, responseWriter)

}

func getZoneState(responseWriter http.ResponseWriter, request *http.Request) {

	log.Debug().Msg("getZoneState")

	homeId := request.URL.Query().Get("homeId")
	zone := request.URL.Query().Get("zone")

	tadoUrl := strings.Replace(zonesStateUrl, "<homeId>", homeId, 1)
	tadoUrl = strings.Replace(tadoUrl, "<zone>", zone, 1)
	requestTado(tadoUrl, responseWriter)

}

func getZoneStateDayReport(responseWriter http.ResponseWriter, request *http.Request) {

	log.Debug().Msg("getZoneStateDayReport")

	homeId := request.URL.Query().Get("homeId")
	zone := request.URL.Query().Get("zone")
	day := request.URL.Query().Get("date")

	tadoUrl := strings.Replace(zoneStateDateReportUrl, "<homeId>", homeId, 1)
	tadoUrl = strings.Replace(tadoUrl, "<zone>", zone, 1)
	tadoUrl = strings.Replace(tadoUrl, "<date>", day, 1)
	requestTado(tadoUrl, responseWriter)

}

func getMe(responseWriter http.ResponseWriter, request *http.Request) {

	log.Debug().Msg("getMe")
	requestTado(meUrl, responseWriter)

}

func loggingMiddleware(next http.Handler) http.Handler {

	log.Debug().Msg("loggingMiddleware")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Debug().Msg(r.RequestURI)
		next.ServeHTTP(w, r)
	})
}

func initApp() {

	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.SetGlobalLevel(zerolog.InfoLevel)

	initEnvironmentVariables()

	if env.debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Debug().Msg("Debug level activated.")
	}

}

func refreshToken() {

	log.Debug().Msg("refreshToken")

	req, err := http.NewRequest("POST", tokenUrl, nil)
	if err != nil {
		log.Print(err)
		os.Exit(1)
	}

	q := req.URL.Query()
	q.Add("client_id", "tado-web-app")
	q.Add("grant_type", "password")
	q.Add("scope", "home.user")
	q.Add("username", env.username)
	q.Add("password", env.password)
	q.Add("client_secret", env.clientSecret)

	req.URL.RawQuery = q.Encode()
	resp, err := http.Post(req.URL.String(), "application/x-www-form-urlencoded", nil)

	if err != nil {
		panic(err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			panic(err)
		}
	}(resp.Body)

	if resp.StatusCode == http.StatusOK {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			panic(err)
		}
		err = json.Unmarshal(body, &token)
		if err != nil {
			panic(err)
		}
	} else {
		log.Debug().Str("request", req.URL.String()).Msg("The request failed.")
		log.Fatal().Str("http-state", resp.Status).Msg("Request failed with error.")
	}

}

func initEnvironmentVariables() {

	log.Info().Msg("Usage:")
	log.Info().Str("apiPort", "Process listening on this port.").Msg("Optional, default is 8080.")
	log.Info().Str("clientSecret", "Client password").Msg("Optional, Default is " + clientSecret)
	log.Info().Str("debug", "false").Msg("Optional: Use debug mode for logging (true | false ). ")
	log.Info().Str("password", "Your password").Msg("Mandatory environment parameter.")
	log.Info().Str("username", "Your username").Msg("Mandatory environment parameter.")

	env.apiPort = getEnv("apiPort", "8080")
	if len(env.apiPort) == 0 {
		log.Fatal().Msg("The environment variable apiPort is unset. Please fix this.")
	}

	env.username = getEnv("username", "")

	if len(env.username) == 0 {
		log.Fatal().Msg("The environment variable username is unset. Please fix this.")
	}

	env.password = getEnv("password", "")
	if len(env.password) == 0 {
		log.Fatal().Msg("The environment variable password is unset. Please fix this.")
	}

	env.clientSecret = getEnv("clientSecret", clientSecret)
	if len(env.clientSecret) == 0 {
		log.Fatal().Msg("The environment variable clientSecret is unset. Please fix this.")
	}

	var err error
	debug := getEnv("debug", "false")
	env.debug, err = strconv.ParseBool(debug)

	if err != nil {
		log.Fatal().Err(err).Str("debug", debug)
	}

	log.Info().Str("debug", strconv.FormatBool(env.debug)).Msg("Log debug mode.")

}

func getEnv(key, fallback string) string {

	log.Debug().Msg("getEnv")

	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}
