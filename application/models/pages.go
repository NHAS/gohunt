package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type CollectedPageDeleteRequest struct {
	Base
}

type CollectedPageDeleteResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type CollectedPageRequest struct {
	PageHTML string `json:"page_html"`
	URI      string `json:"uri"`
}

type CollectedPage struct {
	Base

	gorm.Model
	CollectedPageRequest

	OwnerID   uuid.UUID
	Timestamp int64
}

func (cp *CollectedPage) DTO() CollectedPageDTO {
	var r CollectedPageDTO
	r.UUID = cp.UUID
	r.PageHTML = cp.PageHTML
	r.Timestamp = cp.Timestamp
	r.URI = cp.URI
	return r
}

type CollectedPageDTO struct {
	Base
	CollectedPageRequest
	Timestamp int64 `json:"timestamp"`
}

type CollectedPageResponse struct {
	Results []CollectedPageDTO `json:"results"`
	Total   int64              `json:"total"`
	Success bool               `json:"success"`
}
