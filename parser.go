package uaftlv

import (
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strconv"
)

//TAG types from uaf tlv doc
const (
	UAF_CMD_STATUS_ERR_UNKNOWN      = 0x01
	TAG_UAFV1_REG_ASSERTION         = 0x3E01
	TAG_UAFV1_AUTH_ASSERTION        = 0x3E02
	TAG_UAFV1_KRD                   = 0x3E03
	TAG_UAFV1_SIGNED_DATA           = 0x3E04
	TAG_ATTESTATION_BASIC_FULL      = 0x3E07
	TAG_ATTESTATION_BASIC_SURROGATE = 0x3E08

	TAG_ATTESTATION_CERT         = 0x2E05
	TAG_SIGNATURE                = 0x2E06
	TAG_KEYID                    = 0x2E09
	TAG_FINAL_CHALLENGE_HASH     = 0x2E0A
	TAG_AAID                     = 0x2E0B
	TAG_PUB_KEY                  = 0x2E0C
	TAG_COUNTERS                 = 0x2E0D
	TAG_ASSERTION_INFO           = 0x2E0E
	TAG_AUTHENTICATOR_NONCE      = 0x2E0F
	TAG_TRANSACTION_CONTENT_HASH = 0x2E10

	TAG_ATTESTATION_ECDAA      = 0x3E09
	TAG_EXTENSION              = 0x3E11
	TAG_EXTENSION_NON_CRITICAL = 0x3E1
	TAG_EXTENSION_ID           = 0x2E13
	TAG_EXTENSION_DATA         = 0x2E14
)

var (
	tags = map[int]string{
		TAG_UAFV1_REG_ASSERTION:         "TAG_UAFV1_REG_ASSERTION",
		TAG_UAFV1_AUTH_ASSERTION:        "TAG_UAFV1_AUTH_ASSERTION",
		TAG_UAFV1_KRD:                   "TAG_UAFV1_KRD",
		TAG_UAFV1_SIGNED_DATA:           "TAG_UAFV1_SIGNED_DATA",
		TAG_ATTESTATION_CERT:            "TAG_ATTESTATION_CERT",
		TAG_SIGNATURE:                   "TAG_SIGNATURE",
		TAG_ATTESTATION_BASIC_FULL:      "TAG_ATTESTATION_BASIC_FULL",
		TAG_ATTESTATION_BASIC_SURROGATE: "TAG_ATTESTATION_BASIC_SURROGATE",
		TAG_ATTESTATION_ECDAA:           "TAG_ATTESTATION_ECDAA",
		TAG_KEYID:                       "TAG_KEYID",
		TAG_FINAL_CHALLENGE_HASH:        "TAG_FINAL_CHALLENGE_HASH",
		TAG_AAID:                        "TAG_AAID",
		TAG_PUB_KEY:                     "TAG_PUB_KEY",
		TAG_COUNTERS:                    "TAG_COUNTERS",
		TAG_ASSERTION_INFO:              "TAG_ASSERTION_INFO",
		TAG_AUTHENTICATOR_NONCE:         "TAG_AUTHENTICATOR_NONCE",
		TAG_TRANSACTION_CONTENT_HASH:    "TAG_TRANSACTION_CONTENT_HASH",
		TAG_EXTENSION:                   "TAG_EXTENSION",
		TAG_EXTENSION_NON_CRITICAL:      "TAG_EXTENSION_NON_CRITICAL",
		TAG_EXTENSION_ID:                "TAG_EXTENSION_ID",
		TAG_EXTENSION_DATA:              "TAG_EXTENSION_DATA",
		UAF_CMD_STATUS_ERR_UNKNOWN:      "UAF_CMD_STATUS_ERR_UNKNOWN",
	}

	//errRangeException is thrown when there is not enough bytes to access
	errRangeException = errors.New("Range exception")
)

//Tags is an array of parsed tags
type Tags []*Tag

//Tag is the TLV
type Tag struct {
	ID      uint16 `json:"type"`           //type
	Length  uint16 `json:"length"`         //length
	Value   []byte `json:"value"`          //value
	SubTags Tags   `json:"tags,omitempty"` //sub tags
}

func (tag *Tag) String() string {
	ret := "{ Tag ID: " + strconv.Itoa(int(tag.ID))

	var tagName string
	if name, ok := tags[int(tag.ID)]; ok {
		tagName = name
	} else {
		tagName = "TAG_UNKNOWN"
	}

	ret += " Tag Name: " + tagName
	if tag.Value != nil {
		ret += " Tag Value: " + base64.RawURLEncoding.EncodeToString(tag.Value)
	}

	for _, subTag := range tag.SubTags {
		ret += subTag.String()
	}

	return ret + " }"
}

//Parse parses the data to tags
func Parse(data []byte) (Tags, error) {
	var tags Tags

	for len(data) > 0 {
		tag, err := parseTag(data)
		if err != nil {
			return tags, err
		}

		if 0x1000&tag.ID == 4096 {
			//recursive descent parsing
			subTags, err := Parse(tag.Value)
			if err != nil {
				return tags, err
			}

			tag.SubTags = subTags
		}

		tags = append(tags, tag)

		data = data[4+tag.Length:]
	}

	return tags, nil
}

//parseTLV takes a given bytes and parses with tlv structure
func parseTag(data []byte) (*Tag, error) {
	t := data[:2]
	l := data[2:4]

	tagID := binary.LittleEndian.Uint16(t)
	tagLength := binary.LittleEndian.Uint16(l)

	if len(data)-4 < int(tagLength) {
		return nil, errRangeException
	}

	return &Tag{
		ID:     tagID,
		Length: tagLength,
		Value:  data[4 : tagLength+4],
	}, nil

	//A tag that has the 14th bit (0x2000) set indicates
	//that it is critical and a receiver must abort processing
	//the entire message if it cannot process that tag.
}
