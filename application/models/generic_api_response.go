package models

import (
	"encoding/json"
	"net/http"
)

func writeJson(w http.ResponseWriter, model interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(model)
}

type BooleanResponse struct {
	Success bool `json:"success"`
}

func Boolean(w http.ResponseWriter, success bool) error {
	return writeJson(w, BooleanResponse{
		Success: success,
	})
}

type MessageResponse struct {
	BooleanResponse
	Message string `json:"message"`
}

func Message(w http.ResponseWriter, success bool, msg string) error {
	return writeJson(w, MessageResponse{
		BooleanResponse: BooleanResponse{
			Success: success,
		},
		Message: msg,
	})
}
