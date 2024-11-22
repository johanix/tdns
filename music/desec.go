/*
 * Copyright (c) 2024 Johan Stenstam, johan.stenstam@internetstiftelsen.se
 */
package music

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/go-playground/validator/v10"
	"github.com/spf13/viper"
)

// available throughout package music
var validate = validator.New()

func xxDesecLogin(cc *CliConfig, tokvip *viper.Viper) (DesecLResponse, error) {
	apiurl := viper.GetString("signers.desec.baseurl") + "/auth/login/"
	if err := validate.Var(apiurl, "required,url"); err != nil {
		log.Fatalf("deSEC base URL configured as signers.desec.baseurl required: %v", err)
	}

	email := viper.GetString("signers.desec.email")
	password := viper.GetString("signers.desec.password")
	if err := validate.Var(email, "required,email"); err != nil {
		log.Fatalf("Email address configured as signers.desec.email required: %v", err)
	}

	if err := validate.Var(password, "required,ascii"); err != nil {
		log.Fatalf("Password configured as signers.desec.password required: %v", err)
	}

	dlp := DesecLPost{
		Email:    email,
		Password: password,
	}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(dlp)

	_, buf, err := GenericAPIpost(apiurl, "", "none", bytebuf.Bytes(),
		true, cc.Verbose, cc.Debug, nil)
	if err != nil {
		log.Println("Error from GenericAPIpost:", err)
	}
	// fmt.Printf("Status: %d\n", status)

	var dlr DesecLResponse
	err = json.Unmarshal(buf, &dlr)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}

	// fmt.Printf("Response from Desec login: %v\n", dlr)
	dlr.MaxUnused = ParseDesecDuration(dlr.MaxUnusedRaw)
	dlr.MaxAge = ParseDesecDuration(dlr.MaxAgeRaw)

	tokvip.Set("desec.token", dlr.Token)
	tokvip.Set("desec.created", dlr.Created)
	tokvip.Set("desec.maxunused", dlr.MaxUnused)
	tokvip.Set("desec.maxage", dlr.MaxAge)
	tokvip.WriteConfig()
	return dlr, nil
}

func (api *Api) DesecLogin() (DesecLResponse, error) {
	endpoint := "/auth/login/"

	dlp := DesecLPost{
		Email:    api.Email,
		Password: api.Password,
	}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(dlp)

	status, buf, err := api.NoAuthPost(endpoint, bytebuf.Bytes())
	if err != nil {
		log.Println("Error from api.Post:", err)
	}
	if api.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	var dlr DesecLResponse
	err = json.Unmarshal(buf, &dlr)
	if err != nil {
		log.Fatalf("Error from unmarshal deSEC login response: %v\n", err)
	}

	// fmt.Printf("Response from Desec login: %v\n", dlr)
	dlr.MaxUnused = ParseDesecDuration(dlr.MaxUnusedRaw)
	dlr.MaxAge = ParseDesecDuration(dlr.MaxAgeRaw)

	api.apiKey = dlr.Token // store this token inside the api object

	tokvip := api.TokViper
	if tokvip == nil {
		log.Fatalf("DesecLogin: Error: tokvip unset.\n")
	}
	tokvip.Set("desec.token", dlr.Token)
	tokvip.Set("desec.created", dlr.Created)
	tokvip.Set("desec.maxunused", dlr.MaxUnused)
	tokvip.Set("desec.maxage", dlr.MaxAge)
	tokvip.WriteConfig()
	return dlr, nil
}

func DesecSetupClient(rootcafile string, verbose, debug bool) (*Api, error) {
	baseurl := viper.GetString("signers.desec.baseurl")
	email := viper.GetString("signers.desec.email")
	password := viper.GetString("signers.desec.password")

	if err := validate.Var(baseurl, "required,url"); err != nil {
		log.Fatalf("deSEC base URL configured as signers.desec.baseurl required: %v", err)
	}

	desecapi := NewClient("deSEC", baseurl,
		"",                          // deSEC uses a dynamic token rather than a static key
		"Authorization", rootcafile, // XXX: should use real CA cert
		verbose, debug)

	if err := validate.Var(email, "required,email"); err != nil {
		log.Fatalf("Email address configured as signers.desec.email required: %v", err)
	}

	if err := validate.Var(password, "required,ascii"); err != nil {
		log.Fatalf("Password configured as signers.desec.password required: %v", err)
	}
	desecapi.Email = email
	desecapi.Password = password

	return desecapi, nil
}

func xxDesecTokenRefreshIfNeeded(tokvip *viper.Viper) bool {
	maxdur, _ := time.ParseDuration(tokvip.GetString("desec.maxunused"))
	lasttouch, _ := time.Parse(layout, tokvip.GetString("desec.touched"))
	remaining := time.Until(lasttouch.Add(maxdur))

	fmt.Printf("Time remaining before this token expires: %v\n", remaining)

	if remaining.Minutes() < 2 {
		fmt.Printf("DesecTokenRefresh: Less than 2 minutes remain. Need to login again.\n")
		cc := CliConfig{
			Verbose: true,
			Debug:   false,
		}
		_, err := xxDesecLogin(&cc, tokvip)
		if err != nil {
			fmt.Printf("DesecTokenStillOk: deSEC login failed. Error: %v\n", err)
		} else {
			fmt.Printf("DesecTokenStillOk: deSEC login suceeded.\n")
		}
		// fmt.Printf("Response data from deSEC login: %v\n", dlr)
	}
	return true
}

func (api *Api) DesecTokenRefresh() bool {
	tokvip := api.TokViper
	apikey := api.apiKey
	// perhaps the token is only on disk (due to restart), if so store it in api again
	if apikey == "" {
	   apikey = tokvip.GetString("desec.token")
	   api.apiKey = apikey
	}
	maxdur, _ := time.ParseDuration(tokvip.GetString("desec.maxunused"))
	lasttouch, _ := time.Parse(layout, tokvip.GetString("desec.touched"))
	remaining := time.Until(lasttouch.Add(maxdur))

	fmt.Printf("Time remaining before token '%s' expires: %v\n", apikey, remaining)

	if remaining.Minutes() < 2 {
		fmt.Printf("api.DesecTokenRefresh: Less than 2 minutes remain. Need to login again.\n")

		_, err := api.DesecLogin()
		if err != nil {
			fmt.Printf("DesecTokenRefresh: deSEC login failed. Error: %v\n", err)
		} else {
			fmt.Printf("DesecTokenRefresh: deSEC login suceeded.\n")
		}
		// fmt.Printf("Response data from deSEC login: %v\n", dlr)
	}
	tokvip.Set("desec.touched", time.Now().Format(layout)) // we're about to use API
	return true
}

func DesecLogout(cc *CliConfig, tokvip *viper.Viper) error {
	token := tokvip.GetString("desec.token")
	apiurl := viper.GetString("signers.desec.baseurl") + "/auth/logout/"

	bytebuf := new(bytes.Buffer)
	// fmt.Printf("About to post '%s' to desec\n", string(bytebuf.Bytes()))
	// return nil

	status, _, err := GenericAPIpost(apiurl, token, "Authorization",
		bytebuf.Bytes(), true, cc.Verbose, cc.Debug, nil)
	if err != nil {
		log.Println("Error from GenericAPIpost:", err)
	}
	fmt.Printf("Status: %d\n", status)

	// here we should delete the token file.
	tokvip.Set("desec.token", "")
	tokvip.Set("desec.created", "")
	tokvip.Set("desec.maxunused", "")
	tokvip.Set("desec.maxage", "")
	tokvip.WriteConfig()

	return err
}

func DesecListZone(cc *CliConfig, zone string, tokvip *viper.Viper) ([]DesecZone, error) {
	apiurl := viper.GetString("api.baseurl") + "/domains/"
	if zone != "" {
		apiurl += zone + "/"
	}
	apikey := tokvip.GetString("desec.token")

	status, buf, err := GenericAPIget(apiurl, apikey, "Authorization", true,
		cc.Verbose, cc.Debug, nil)
	if status == 401 {
		return []DesecZone{}, fmt.Errorf("401 Unauthorized.")
	}
	if err != nil {
		log.Println("Error from GenericAPIget:", err)
	}
	fmt.Printf("Status: %d\n", status)

	var zl []DesecZone
	err = json.Unmarshal(buf, &zl)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}

	return zl, nil
}

func DesecAddZone(cc *CliConfig, zone string, tokvip *viper.Viper) (DesecZone, error) {
	var dz DesecZone

	apiurl := viper.GetString("api.baseurl") + "/domains/"
	apikey := tokvip.GetString("desec.token")

	data := ZoneName{Name: zone}

	bytebuf := new(bytes.Buffer)
	json.NewEncoder(bytebuf).Encode(data)

	// fmt.Printf("About to post to desec: '%s'\n", string(bytebuf.Bytes()))
	// os.Exit(1)

	status, buf, err := GenericAPIpost(apiurl, apikey, "Authorization",
		bytebuf.Bytes(), true, cc.Verbose, cc.Debug, nil)
	if status == 401 {
		return DesecZone{}, fmt.Errorf("401 Unauthorized.")
	}
	if err != nil {
		log.Println("Error from GenericAPIpost:", err)
		return dz, err
	}
	if cc.Verbose {
		fmt.Printf("Status: %d\n", status)
	}

	fmt.Printf("Response from Desec add zone: %v\n", string(buf))
	err = json.Unmarshal(buf, &dz)
	if err != nil {
		log.Fatalf("Error from unmarshal: %v\n", err)
	}

	return dz, err
}

func DesecDeleteZone(cc *CliConfig, zone string, tokvip *viper.Viper) error {
	apiurl := viper.GetString("api.baseurl") + "/domains/" + zone + "/"
	apikey := tokvip.GetString("desec.token")

	status, _, err := GenericAPIdelete(apiurl, apikey, "Authorization",
		true, cc.Verbose, cc.Debug, nil)
	if cc.Verbose {
		fmt.Printf("Status: %d\n", status)
	}
	if status == 401 {
		return fmt.Errorf("401 Unauthorized.")
	}
	if status == 204 {
		return nil // all ok
	}
	if err != nil {
		log.Println("Error from GenericAPIdelete:", err)
		return err
	}
	return nil
}
