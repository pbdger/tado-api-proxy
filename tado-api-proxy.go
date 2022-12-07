package main

import (
	"encoding/json"
	"errors"
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

type StateReport struct {
	CallForHeat struct {
		DataIntervals []struct {
			From  time.Time `json:"from"`
			To    time.Time `json:"to"`
			Value string    `json:"value"`
		} `json:"dataIntervals"`
		TimeSeriesType string `json:"timeSeriesType"`
		ValueType      string `json:"valueType"`
	} `json:"callForHeat"`
	HoursInDay int `json:"hoursInDay"`
	Interval   struct {
		From time.Time `json:"from"`
		To   time.Time `json:"to"`
	} `json:"interval"`
	MeasuredData struct {
		Humidity struct {
			DataPoints []struct {
				Timestamp time.Time `json:"timestamp"`
				Value     float64   `json:"value"`
			} `json:"dataPoints"`
			Max            float64 `json:"max"`
			Min            float64 `json:"min"`
			PercentageUnit string  `json:"percentageUnit"`
			TimeSeriesType string  `json:"timeSeriesType"`
			ValueType      string  `json:"valueType"`
		} `json:"humidity"`
		InsideTemperature struct {
			DataPoints []struct {
				Timestamp time.Time `json:"timestamp"`
				Value     struct {
					Celsius    float64 `json:"celsius"`
					Fahrenheit float64 `json:"fahrenheit"`
				} `json:"value"`
			} `json:"dataPoints"`
			Max struct {
				Celsius    float64 `json:"celsius"`
				Fahrenheit float64 `json:"fahrenheit"`
			} `json:"max"`
			Min struct {
				Celsius    float64 `json:"celsius"`
				Fahrenheit float64 `json:"fahrenheit"`
			} `json:"min"`
			TimeSeriesType string `json:"timeSeriesType"`
			ValueType      string `json:"valueType"`
		} `json:"insideTemperature"`
		MeasuringDeviceConnected struct {
			DataIntervals []struct {
				From  time.Time `json:"from"`
				To    time.Time `json:"to"`
				Value bool      `json:"value"`
			} `json:"dataIntervals"`
			TimeSeriesType string `json:"timeSeriesType"`
			ValueType      string `json:"valueType"`
		} `json:"measuringDeviceConnected"`
	} `json:"measuredData"`
	Settings struct {
		DataIntervals []struct {
			From  time.Time `json:"from"`
			To    time.Time `json:"to"`
			Value struct {
				Power       string      `json:"power"`
				Temperature interface{} `json:"temperature"`
				Type        string      `json:"type"`
			} `json:"value"`
		} `json:"dataIntervals"`
		TimeSeriesType string `json:"timeSeriesType"`
		ValueType      string `json:"valueType"`
	} `json:"settings"`
	Stripes struct {
		DataIntervals []struct {
			From  time.Time `json:"from"`
			To    time.Time `json:"to"`
			Value struct {
				Setting struct {
					Power       string      `json:"power"`
					Temperature interface{} `json:"temperature"`
					Type        string      `json:"type"`
				} `json:"setting"`
				StripeType string `json:"stripeType"`
			} `json:"value"`
		} `json:"dataIntervals"`
		TimeSeriesType string `json:"timeSeriesType"`
		ValueType      string `json:"valueType"`
	} `json:"stripes"`
	Weather struct {
		Condition struct {
			DataIntervals []struct {
				From  time.Time `json:"from"`
				To    time.Time `json:"to"`
				Value struct {
					State       string `json:"state"`
					Temperature struct {
						Celsius    float64 `json:"celsius"`
						Fahrenheit float64 `json:"fahrenheit"`
					} `json:"temperature"`
				} `json:"value"`
			} `json:"dataIntervals"`
			TimeSeriesType string `json:"timeSeriesType"`
			ValueType      string `json:"valueType"`
		} `json:"condition"`
		Slots struct {
			Slots struct {
				_04_00 struct {
					State       string `json:"state"`
					Temperature struct {
						Celsius    float64 `json:"celsius"`
						Fahrenheit float64 `json:"fahrenheit"`
					} `json:"temperature"`
				} `json:"04:00"`
				_08_00 struct {
					State       string `json:"state"`
					Temperature struct {
						Celsius    float64 `json:"celsius"`
						Fahrenheit float64 `json:"fahrenheit"`
					} `json:"temperature"`
				} `json:"08:00"`
				_12_00 struct {
					State       string `json:"state"`
					Temperature struct {
						Celsius    float64 `json:"celsius"`
						Fahrenheit float64 `json:"fahrenheit"`
					} `json:"temperature"`
				} `json:"12:00"`
			} `json:"slots"`
			TimeSeriesType string `json:"timeSeriesType"`
			ValueType      string `json:"valueType"`
		} `json:"slots"`
		Sunny struct {
			DataIntervals []struct {
				From  time.Time `json:"from"`
				To    time.Time `json:"to"`
				Value bool      `json:"value"`
			} `json:"dataIntervals"`
			TimeSeriesType string `json:"timeSeriesType"`
			ValueType      string `json:"valueType"`
		} `json:"sunny"`
	} `json:"weather"`
	ZoneType string `json:"zoneType"`
}

type Request struct {
	Url   string `json:"url"`
	State string `json:"state"`
}

type ErrorResponse struct {
	Error   string  `json:"error"`
	Request Request `json:"request"`
}

type EnvironmentKey struct {
	apiPort      string
	clientSecret string
	debug        string
	password     string
	username     string
}

type RequestParameter struct {
	homeId   string
	zone     string
	date     string
	dateFrom string
	dateTo   string
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
	env    environment
	token  TokenResponse
	envKey = EnvironmentKey{
		apiPort:      "apiPort",
		clientSecret: "clientSecret",
		password:     "password",
		debug:        "debug",
		username:     "username",
	}
	requestParameter = RequestParameter{
		homeId:   "homeId",
		date:     "date",
		dateTo:   "dateTo",
		dateFrom: "dateFrom",
		zone:     "zone",
	}
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
	router.HandleFunc("/weatherHistory", getWeatherHistory)
	router.HandleFunc("/zones", getZones)
	router.HandleFunc("/zoneState", getZoneState)
	router.HandleFunc("/zoneStateDateReport", getZoneStateDayReport)

	router.Use(loggingMiddleware)
	http.Handle("/", router)
	log.Info().Msg("Ready. Listen on port " + env.apiPort)
	log.Fatal().Err(http.ListenAndServe(":"+env.apiPort, nil))

}

func getWeatherHistory(responseWriter http.ResponseWriter, request *http.Request) {

	log.Debug().Msg("getZoneStateDayReport")

	homeId, err := checkParameter(requestParameter.homeId, request, responseWriter)
	if err != nil {
		return
	}

	zone, err := checkParameter(requestParameter.zone, request, responseWriter)
	if err != nil {
		return
	}

	dateFrom, err := checkParameter(requestParameter.dateFrom, request, responseWriter)
	if err != nil {
		return
	}

	dateTo, err := checkParameter(requestParameter.dateTo, request, responseWriter)
	if err != nil {
		return
	}

	content := ""
	content = content + "#group,false,false,true,true,false,false,true,true,true" + "\n"
	content = content + "#datatype,string,long,dateTime:RFC3339,dateTime:RFC3339,dateTime:RFC3339,double,string,string,string" + "\n"
	content = content + "#default,last,,,,,,,," + "\n"
	content = content + ",result,table,_start,_stop,_time,_value,_field,_measurement,room" + "\n"
	temperatureLineTemplate := ",,0,2022-12-07T17:44:21.54868924Z,2022-12-07T18:44:21.54868924Z,<time>,<temperature>,activityDataPoints_heatingPower_percentage,tado,Badezimmer" + "\n"

	for i := 1; i < 9; i++ {

		from, _ := time.Parse("2006-01-02", dateFrom)
		to, _ := time.Parse("2006-01-02", dateTo)
		currentDate := from

		if i == 1 {
			temperatureLineTemplate = ",,0,2022-12-07T17:44:21.54868924Z,2022-12-07T18:44:21.54868924Z,<time>,<temperature>,activityDataPoints_heatingPower_percentage,tado,Büro" + "\n"
			zone = "1"
		}

		if i == 2 {
			temperatureLineTemplate = ",,0,2022-12-07T17:44:21.54868924Z,2022-12-07T18:44:21.54868924Z,<time>,<temperature>,activityDataPoints_heatingPower_percentage,tado,Badezimmer" + "\n"
			zone = "2"
		}
		if i == 3 {
			temperatureLineTemplate = ",,0,2022-12-07T17:44:21.54868924Z,2022-12-07T18:44:21.54868924Z,<time>,<temperature>,activityDataPoints_heatingPower_percentage,tado,Gäste WC" + "\n"
			zone = "3"
		}
		if i == 4 {
			temperatureLineTemplate = ",,0,2022-12-07T17:44:21.54868924Z,2022-12-07T18:44:21.54868924Z,<time>,<temperature>,activityDataPoints_heatingPower_percentage,tado,Wohnzimmer" + "\n"
			zone = "4"
		}
		if i == 5 {
			temperatureLineTemplate = ",,0,2022-12-07T17:44:21.54868924Z,2022-12-07T18:44:21.54868924Z,<time>,<temperature>,activityDataPoints_heatingPower_percentage,tado,Datsche" + "\n"
			zone = "5"
		}
		if i == 6 {
			temperatureLineTemplate = ",,0,2022-12-07T17:44:21.54868924Z,2022-12-07T18:44:21.54868924Z,<time>,<temperature>,activityDataPoints_heatingPower_percentage,tado,Schlafzimmer" + "\n"
			zone = "6"
		}
		if i == 7 {
			temperatureLineTemplate = ",,0,2022-12-07T17:44:21.54868924Z,2022-12-07T18:44:21.54868924Z,<time>,<temperature>,activityDataPoints_heatingPower_percentage,tado,Datsche Büro" + "\n"
			zone = "12"
		}
		if i == 8 {
			temperatureLineTemplate = ",,0,2022-12-07T17:44:21.54868924Z,2022-12-07T18:44:21.54868924Z,<time>,<temperature>,activityDataPoints_heatingPower_percentage,tado,Datsche Bad" + "\n"
			zone = "13"
		}

		for {
			log.Info().Msgf("Date %v", currentDate)
			stateReport, err := findWeatherForDate(currentDate, homeId, zone)
			for _, s := range stateReport.CallForHeat.DataIntervals {
				var value float64 = 0.0
				switch s.Value {
				case "LOW":
					value = 25.0
				case "MEDIUM":
					value = 60.0
				case "HIGH":
					value = 100.0
				}
				temperature := fmt.Sprintf("%f", value)
				time := s.From.Format(time.RFC3339)
				temperatureLine := strings.Replace(temperatureLineTemplate, "<time>", time, 1)
				temperatureLine = strings.Replace(temperatureLine, "<temperature>", temperature, 1)
				content = content + temperatureLine
			}
			if err != nil {

			}
			currentDate = currentDate.Add(time.Hour * 24)
			if currentDate.Unix() > to.Unix() {
				break
			}
		}
	}

	responseWriter.Write([]byte(content))
	responseWriter.WriteHeader(http.StatusOK)

}

func findWeatherForDate(date time.Time, homeId string, zone string) (stateReport StateReport, err error) {

	tadoUrl := strings.Replace(zoneStateDateReportUrl, "<homeId>", homeId, 1)
	tadoUrl = strings.Replace(tadoUrl, "<zone>", zone, 1)
	tadoUrl = strings.Replace(tadoUrl, "<date>", date.Format("2006-01-02"), 1)

	content, err := getTadoData(tadoUrl)
	if err != nil {
		return stateReport, err
	}

	err = json.Unmarshal(content, &stateReport)
	if err != nil {
		return stateReport, err
	}
	return stateReport, nil

}

func getTadoData(tadoUrl string) (content []byte, err error) {

	log.Debug().Msg("requestTado")

	client := &http.Client{}
	req, _ := http.NewRequest("GET", tadoUrl, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token.AccessToken)
	resp, _ := client.Do(req)

	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		log.Error().Str("http-state", resp.Status).Str("url", tadoUrl).Msg("Request failed with error.")
		return respBody, errors.New("request failed with error")
	}

	return respBody, nil

}

func requestTado(tadoUrl string, responseWriter http.ResponseWriter) {

	log.Debug().Msg("requestTado")

	client := &http.Client{}
	req, _ := http.NewRequest("GET", tadoUrl, nil)
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Authorization", "Bearer "+token.AccessToken)
	resp, _ := client.Do(req)

	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusOK {
		responseWriter.Write(respBody)
		responseWriter.WriteHeader(http.StatusOK)
	} else {
		errorResponse := ErrorResponse{
			Request: Request{
				Url:   tadoUrl,
				State: resp.Status,
			},
			Error: "Request failed with error",
		}

		enc := json.NewEncoder(responseWriter)
		enc.SetIndent("", "    ")
		if err := enc.Encode(errorResponse); err != nil {
			panic(err)
		}
		responseWriter.WriteHeader(http.StatusInternalServerError)
		log.Error().Str("http-state", resp.Status).Str("url", tadoUrl).Msg("Request failed with error.")
	}

}

func getHome(responseWriter http.ResponseWriter, request *http.Request) {

	log.Debug().Msg("getHome")

	homeId, err := checkParameter(requestParameter.homeId, request, responseWriter)
	if err != nil {
		return
	}

	tadoUrl := strings.Replace(homesUrl, "<homeId>", homeId, 1)
	requestTado(tadoUrl, responseWriter)

}

func checkParameter(parameterKey string, request *http.Request, writer http.ResponseWriter) (parameter string, err error) {

	parameter = request.URL.Query().Get(parameterKey)
	if parameter == "" {
		errorResponse := ErrorResponse{
			Request: Request{
				Url:   "",
				State: "",
			},
			Error: "Missing parameter " + parameterKey,
		}

		enc := json.NewEncoder(writer)
		enc.SetIndent("", "    ")
		if err := enc.Encode(errorResponse); err != nil {
			panic(err)
		}
		writer.WriteHeader(http.StatusInternalServerError)
		return "", errors.New(errorResponse.Error)
	}

	return parameter, nil

}

func getZones(responseWriter http.ResponseWriter, request *http.Request) {

	log.Debug().Msg("getZones")

	homeId, err := checkParameter(requestParameter.homeId, request, responseWriter)
	if err != nil {
		return
	}

	tadoUrl := strings.Replace(zonesUrl, "<homeId>", homeId, 1)
	requestTado(tadoUrl, responseWriter)

}

func getWeather(responseWriter http.ResponseWriter, request *http.Request) {

	log.Debug().Msg("getWeather")

	homeId, err := checkParameter(requestParameter.homeId, request, responseWriter)
	if err != nil {
		return
	}

	tadoUrl := strings.Replace(weatherUrl, "<homeId>", homeId, 1)
	requestTado(tadoUrl, responseWriter)

}

func getZoneState(responseWriter http.ResponseWriter, request *http.Request) {

	log.Debug().Msg("getZoneState")

	homeId, err := checkParameter(requestParameter.homeId, request, responseWriter)
	if err != nil {
		return
	}

	zone, err := checkParameter(requestParameter.zone, request, responseWriter)
	if err != nil {
		return
	}

	tadoUrl := strings.Replace(zonesStateUrl, "<homeId>", homeId, 1)
	tadoUrl = strings.Replace(tadoUrl, "<zone>", zone, 1)
	requestTado(tadoUrl, responseWriter)

}

func getZoneStateDayReport(responseWriter http.ResponseWriter, request *http.Request) {

	log.Debug().Msg("getZoneStateDayReport")

	homeId, err := checkParameter(requestParameter.homeId, request, responseWriter)
	if err != nil {
		return
	}

	zone, err := checkParameter(requestParameter.zone, request, responseWriter)
	if err != nil {
		return
	}

	date, err := checkParameter(requestParameter.date, request, responseWriter)
	if err != nil {
		return
	}

	tadoUrl := strings.Replace(zoneStateDateReportUrl, "<homeId>", homeId, 1)
	tadoUrl = strings.Replace(tadoUrl, "<zone>", zone, 1)
	tadoUrl = strings.Replace(tadoUrl, "<date>", date, 1)
	requestTado(tadoUrl, responseWriter)

}

func getMe(responseWriter http.ResponseWriter, _ *http.Request) {

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
	log.Info().Str(envKey.apiPort, "Process listening on this port.").Msg("Optional, default is 8080.")
	log.Info().Str(envKey.clientSecret, "Client password").Msg("Optional, Default is " + clientSecret)
	log.Info().Str(envKey.debug, "false").Msg("Optional: Use debug mode for logging (true | false ). ")
	log.Info().Str(envKey.password, "Your password").Msg("Mandatory environment parameter.")
	log.Info().Str(envKey.username, "Your username").Msg("Mandatory environment parameter.")

	env.apiPort = getEnv(envKey.apiPort, "8080")
	if len(env.apiPort) == 0 {
		log.Fatal().Msg("The environment variable apiPort is unset. Please fix this.")
	}

	env.username = getEnv(envKey.username, "")

	if len(env.username) == 0 {
		log.Fatal().Msg("The environment variable username is unset. Please fix this.")
	}

	env.password = getEnv(envKey.password, "")
	if len(env.password) == 0 {
		log.Fatal().Msg("The environment variable password is unset. Please fix this.")
	}

	env.clientSecret = getEnv(envKey.clientSecret, clientSecret)
	if len(env.clientSecret) == 0 {
		log.Fatal().Msg("The environment variable clientSecret is unset. Please fix this.")
	}

	var err error
	debug := getEnv(envKey.debug, "false")
	env.debug, err = strconv.ParseBool(debug)

	if err != nil {
		log.Fatal().Err(err).Str(envKey.debug, debug)
	}

	log.Info().Str(envKey.debug, strconv.FormatBool(env.debug)).Msg("Log debug mode.")

}

func getEnv(key, fallback string) string {

	log.Debug().Msg("getEnv")

	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}
