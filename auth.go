package steam_go

import (
	"errors"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"fmt"
)

var (
	steamLogin = "https://steamcommunity.com/openid/login"

	openIdMode       = "checkid_setup"
	openIdNs         = "http://specs.openid.net/auth/2.0"
	openIdIdentifier = "http://specs.openid.net/auth/2.0/identifier_select"

	validationRegexp       = regexp.MustCompile("^(http|https)://steamcommunity.com/openid/id/[0-9]{15,25}$")
	digitsExtractionRegexp = regexp.MustCompile("\\D+")
)

type OpenId struct {
	root      string
	returnUrl string
	data      url.Values
}

func NewOpenId(r *http.Request) *OpenId {
	id := new(OpenId)

	proto := "http://"
	if r.TLS != nil {
		proto = "https://"
	}
	id.root = proto + r.Host

	uri := r.RequestURI
	if i := strings.Index(uri, "openid"); i != -1 {
		uri = uri[0 : i-1]
	}
	id.returnUrl = id.root + uri
	switch r.Method {
	case "POST":
		id.data = r.Form
	case "GET":
		id.data = r.URL.Query()
	}

	return id
}

func (id OpenId) AuthUrl(returnUrl string, realmUrl string) string {
	if returnUrl == "" {
		returnUrl = id.returnUrl
	}
	if realmUrl == "" {
	    realmUrl = id.root
    }

	data := map[string]string{
		"openid.claimed_id": openIdIdentifier,
		"openid.identity":   openIdIdentifier,
		"openid.mode":       openIdMode,
		"openid.ns":         openIdNs,
		"openid.realm":      realmUrl,
		"openid.return_to":  returnUrl,
	}

	i := 0
	urlSteam := steamLogin + "?"
	for key, value := range data {
		urlSteam += key + "=" + value
		if i != len(data)-1 {
			urlSteam += "&"
		}
		i++
	}
	return urlSteam
}

func (id *OpenId) ValidateAndGetId() (string, error) {
	if id.Mode() != "id_res" {
		return "", errors.New("mode must equal to \"id_res\"")
	}

	if id.data.Get("openid.return_to") != id.returnUrl {
		return "", errors.New("the \"return_to url\" must match the url of current request")
	}

	params := make(url.Values)
	params.Set("openid.assoc_handle", id.data.Get("openid.assoc_handle"))
	params.Set("openid.signed", id.data.Get("openid.signed"))
	params.Set("openid.sig", id.data.Get("openid.sig"))
	params.Set("openid.ns", id.data.Get("openid.ns"))

	split := strings.Split(id.data.Get("openid.signed"), ",")
	for _, item := range split {
		params.Set("openid."+item, id.data.Get("openid."+item))
	}
	params.Set("openid.mode", "check_authentication")

	resp, err := http.PostForm(steamLogin, params)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	response := strings.Split(string(content), "\n")
	if response[0] != "ns:"+openIdNs {
		return "", errors.New("wrong ns in the response")
	}
	if strings.HasSuffix(response[1], "false") {
		return "", errors.New("unable validate openId")
	}

	openIdUrl := id.data.Get("openid.claimed_id")
	if !validationRegexp.MatchString(openIdUrl) {
		return "", errors.New("invalid steam id pattern")
	}

	return digitsExtractionRegexp.ReplaceAllString(openIdUrl, ""), nil
}

func (id OpenId) ValidateAndGetUser(apiKey string) (*PlayerSummaries, error) {
	steamId, err := id.ValidateAndGetId()
	if err != nil {
		return nil, err
	}
	return GetPlayerSummaries(steamId, apiKey)
}

func (id OpenId) Mode() string {
	return id.data.Get("openid.mode")
}
