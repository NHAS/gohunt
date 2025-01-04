package models

import (
	"fmt"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type InjectionDeleteRequest struct {
	Base
}

type BulkInjectionDeleteRequest struct {
	VictimIP string `json:"ip"`
	URI      string `json:"uri"`
}

type BulkInjectionDeleteResponse struct {
	Results []Injection `json:"results"`
	Success bool        `json:"success"`
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
	LocalStorage       string    `json:"injection_key"`
	OwnerID            uuid.UUID `json:"-"`
	CorrelatedRequest  string    `json:"local_storage"`
}

func (i *Injection) BriefString() string {
	return fmt.Sprintf(
		"Victim IP: %q\nReferer: %q\nUser-Agent: %q",
		i.VictimIP,
		i.Referer,
		i.UserAgent,
	)
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
