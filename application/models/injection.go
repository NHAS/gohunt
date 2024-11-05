package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type InjectionDeleteRequest struct {
	Base
}

type InjectionAPIResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// Has no DTO object as the contents are not sensitive
type Injection struct {
	gorm.Model `json:"-"`

	Base
	VulnerablePage     string    `json:"vulnerable_page"`
	VictimIP           string    `json:"victim_ip"`
	Referer            string    `json:"referer"`
	UserAgent          string    `json:"user_agent"`
	Cookies            string    `json:"cookies"`
	DOM                string    `json:"dom"`
	Origin             string    `json:"origin"`
	Screenshot         string    `json:"screenshot"`
	InjectionTimestamp int64     `json:"injection_timestamp"`
	BrowserTime        int64     `json:"browser_time"`
	OwnerID            uuid.UUID `json:"-"`
	CorrelatedRequest  string    `json:"correlated_request"`
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
