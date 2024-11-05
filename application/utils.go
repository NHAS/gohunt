package application

import (
	"encoding/json"
	"io"
)

func jsonDecoder(r io.Reader) *json.Decoder {
	decoder := json.NewDecoder(r)
	decoder.DisallowUnknownFields()

	return decoder
}
