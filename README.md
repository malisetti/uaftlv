```
const posStr = "AT5HAwM-ywALLgkAMTM4QSM0MjAyDi4HAAEAAQIAAQEKLiAA8y7kunvd44-a9X2uorVkBXY9O2cBjq9eoMJ_dMHp9N8JLiAAzsfjhbCwYi_w-zHTiFvJj7cv-siLlds5DaqhxS9Wt9YNLggAAAAAAAAAAAAMLlsAMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYF90PjVZI3r6boxoZU7coML95fq-aaBMiBlCtD1OakDWlyfOvy3XNGq0VgGi07907M7nbYQk4X7DxvRNw32i_gc-dAIGLkcAMEUCIA5ini_jQ_LbeISWDTjXySWZtFq5b5fJpd-ZPttbhfDtAiEA3n2RnSN-pE9GvQOyBv7CMAxvbTdro2dtQrYXwL0iuJQFLiUCMIICITCCAccCAQEwCQYHKoZIzj0EATCBnDELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMREwDwYDVQQHEwhTYW4gSm9zZTEYMBYGA1UEChMPU3luYXB0aWNzLCBJbmMuMQwwCgYDVQQLEwNCUEQxGTAXBgNVBAMTEFNtYmF0IFRvbm95YW4gQ0ExKjAoBgkqhkiG9w0BCQEWG3NtYmF0LnRvbm95YW5Ac3luYXB0aWNzLmNvbTAeFw0xNDA5MTYxOTI3MjZaFw0xOTA5MTYxOTI3MjZaMIGcMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQ0ExETAPBgNVBAcTCFNhbiBKb3NlMRgwFgYDVQQKEw9TeW5hcHRpY3MsIEluYy4xDDAKBgNVBAsTA0JQRDEZMBcGA1UEAxMQU21iYXQgVG9ub3lhbiBDQTEqMCgGCSqGSIb3DQEJARYbc21iYXQudG9ub3lhbkBzeW5hcHRpY3MuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9_MKXwdtfkbsFR2kvtnSlnesBJdF5acPuUBswKcnQhAHDv7Btf9LHQppfTOrSl4ndkLasRfmoTANz7nEGM3RzTAJBgcqhkjOPQQBA0kAMEYCIQDqU8DxhlwEe4gfyJDVTyWNdbbzOuluMHk3j31DHYsyQgIhANkuIVsk9QcaiD-ZR-RDoGmUEIj97TUYCSiSTAXgACuW"

const masStr = "AT7mAQM-mgELLgkAMDA1MyMwMDAxDi4HAAEAAQEAAAEKLiAA53YZGy8Jq5BZBS0QsnQLghxro1VRRiw1a26PuRme8yQJLgsBVFVsSFZFRm5SVUZOUWsxSFFubHhSMU5OTkRsQlowVkhRME54UjFOTk5EbEJkMFZJUWtocmQyUjNTVUpCVVZGblJVSnlXRkpsVVdSVmJuazJkWGcxY0RCTGVscFdkVXR2Y0hNdFdtSTNSa0pEVVRSclNscHhObHBNTW1kRFoxbEpTMjlhU1hwcU1FUkJVV1ZvVWtGT1EwRkJVVlpCYWxkVmVHUjJUVmxYZUcwNWNtaHhlV3MwWkdkQlltOU9RelUxV21nMWRuWlVURlJKVkUxVE1GRTJVR2swWDBsS1NXY3lkR1p6UVU5TU1EYzRlbEZwVDFGdlNreHBUMlozWlVFeE5WUnlTak0wYjFnDS4EAAAAAAAMLkEABBUCNZTF28xhbGb2uGrKTh2ABug0LnlmHm-9MtMhMxLRDo-Lj8gkiDa1-wA4vTvzNCI5CgkuI5_B4DXlOsnfihcIPgg-RAAGLkAARoRpmmsMoXASuCzxewSKzyWXC0we58rzVGDT_G3kIKeH3OGyDVzYyjxSDhHwwxRe-_sY3kEVVB2OAMn-u0jPmA"

func main() {
	b, err := base64.RawURLEncoding.DecodeString(posStr)
	if err != nil {
		log.Fatal(err)
	}

	tags, err := Parse(b)
	if err != nil {
		log.Fatal(err)
	}

	buf, err := json.Marshal(tags)

	log.Println(string(buf), err)
}
```