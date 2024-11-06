package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type InjectionDeleteRequest struct {
	Base
}

// Has no DTO object as the contents are not sensitive
type Injection struct {
	gorm.Model `json:"-"`

	Base
	VulnerablePage     string    `json:"uri"`
	VictimIP           string    `json:"ip"`
	Referer            string    `json:"referrer"`
	UserAgent          string    `json:"user-agent"`
	Cookies            string    `json:"cookies"`
	DOM                string    `json:"dom"`
	Origin             string    `json:"origin"`
	Screenshot         string    `json:"screenshot"`
	InjectionTimestamp int64     `json:"injection_timestamp"`
	BrowserTime        int64     `json:"browser-time"`
	OwnerID            uuid.UUID `json:"-"`
	CorrelatedRequest  string    `json:"injection_key"`
}

type InjectionRequest struct {
	Base `json:"-"`

	gorm.Model          `json:"-"`
	InjectionKey        string `json:"injection_key"`
	Request             string `json:"request"`
	OwnerCorrelationKey string `json:"owner_correlation_key"`
}

type InjectionResponse struct {
	Results []Injection `json:"results"`
	Total   int64       `json:"total"`
	Success bool        `json:"success"`
}

type InjectionEmailRequest struct {
	Base
}
