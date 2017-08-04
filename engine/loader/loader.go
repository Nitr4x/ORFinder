package loader

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
)

const (
	URL         = "aHR0cHM6Ly9jb3VudHJ5aXBibG9ja3MubmV0L2NvdW50cnlfc2VsZWN0aW9uLnBocA=="
	COOKIE      = "X191dG1hPTE1MTAyMDIwMy4xNzY3NzU0MTA4LjE1MDA1NjU1ODMuMTUwMDU2NTU4My4xNTAwNTY1NTgzLjE7X191dG16PTE1MTAyMDIwMy4xNTAwNTY1NTgzLjEuMS51dG1jc3I9KGRpcmVjdCl8dXRtY2NuPShkaXJlY3QpfHV0bWNtZD0obm9uZSk7IFBIUFNFU1NJRD01NDZmZTgxNjQ5NzliMjc3MmI4Mzk0NzhiYWU5MWI0ZQ=="
	CONTENTTYPE = "YXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVk"
	HOST        = "d3d3LmNvdW50cnlpcGJsb2Nrcy5uZXQ="
	REFERER     = "aHR0cHM6Ly93d3cuY291bnRyeWlwYmxvY2tzLm5ldC9jb3VudHJ5X3NlbGVjdGlvbi5waHA="
)

// Function decode(str string) string
// Decode the giver string
// Return the decoded string
func decode(str string) string {
	res, _ := base64.StdEncoding.DecodeString(str)

	return string(res)
}

// Function getIPsRange(countrCode string) []string
// Get all the IP ranges corresponding to the given country code
// Return an array of IP ranges
func getIPsRange(countryCode string) []string {
	data := url.Values{
		"countries[]": {countryCode},
		"format1":     {"1"},
		"get_acl":     {"Create+ACL"},
	}

	var client = &http.Client{}

	req, _ := http.NewRequest("POST", decode(URL), bytes.NewBufferString(data.Encode()))

	req.Header.Add("Cookie", decode(COOKIE))
	req.Header.Add("Content-Type", decode(CONTENTTYPE))
	req.Header.Add("Host", decode(HOST))
	req.Header.Add("Referer", decode(REFERER))

	resp, err := client.Do(req)
	if err != nil {
		log.Fatal(err)
	}

	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)

	r, _ := regexp.Compile("\\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\/(3[0-2]|[1-2]?[0-9])\\b")

	return r.FindAllString(string(body), -1)
}

// Function Load(countryCode string) []string
// Loader entry point
// Return an array of IP ranges
func Load(countryCode string) []string {
	return getIPsRange(countryCode)
}
