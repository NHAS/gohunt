package models

import (
	"crypto/rand"
	"encoding/hex"
	"io"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

// Models
type User struct {
	Base       `json:"-"`
	gorm.Model `json:"-"`
	UserDTO

	Password string `gorm:"not null"`
}

// Returns true when bcrypt compare returns no error
func (u *User) ComparePassword(password string) bool {
	// Compare the stored hashed password with the provided password
	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) == nil
}

func (u *User) BeforeCreate(tx *gorm.DB) (err error) {
	if err := u.Base.BeforeCreate(tx); err != nil {
		return err
	}

	return u.UserDTO.BeforeCreate(tx)
}

func (u *User) DTO() UserDTO {
	return u.UserDTO
}

type UserDTO struct {
	FullName            string   `json:"full_name"`
	Email               string   `gorm:"not null" json:"email"`
	Username            string   `gorm:"unique;not null" json:"username"`
	PGPKey              string   `json:"pgp_key"`
	EmailEnabled        bool     `json:"email_enabled"`
	Domain              string   `gorm:"unique;not null" json:"domain"`
	ChainloadURI        string   `json:"chainload_uri"`
	OwnerCorrelationKey string   `gorm:"unique" json:"owner_correlation_key"`
	PageCollectionPaths []string `gorm:"serializer:json" json:"page_collection_paths_list"`
	WebhooksList        []string `gorm:"serializer:json" json:"webhooks_list"`
	WebhooksEnabled     bool     `json:"webhooks_enabled"`

	IsAdmin bool `json:"is_admin"`

	SSOSubject string `gorm:"unqiue" json:"sso_subject"`
}

func (u *UserDTO) BeforeCreate(tx *gorm.DB) (err error) {
	b := make([]byte, 50)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return err
	}
	u.OwnerCorrelationKey = hex.EncodeToString(b)
	return
}

type CreateUserRequest struct {
	Email        string `json:"email"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	Domain       string `json:"domain"`
	EmailEnabled bool   `json:"email_enabled"`
	Fullname     string `json:"full_name"`
}

type EditUserRequest struct {
	FullName        string `json:"full_name"`
	Email           string `gorm:"not null" json:"email"`
	Password        string `json:"password"`
	CurrentPassword string `json:"current_password"`

	EmailEnabled        bool     `json:"email_enabled"`
	ChainloadURI        string   `json:"chainload_uri"`
	PageCollectionPaths []string `json:"page_collection_paths_list"`
	PGPKey              string   `json:"pgp_key"`

	WebhooksList   []string `json:"webhooks_list"`
	WebhookEnabled bool     `json:"webhooks_enabled"`
}

type LoginUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

const (
	UserIDSession = "user_id"
)

type AdminUserDTO struct {
	Base
	Username   string   `json:"username"`
	Domain     string   `json:"domain"`
	FullName   string   `json:"full_name"`
	Email      string   `json:"email"`
	IsAdmin    bool     `json:"is_admin"`
	Attributes []string `json:"attributes"`
}

type GetUsersResponse struct {
	Results []AdminUserDTO `json:"results"`
	Success bool           `json:"success"`
	Total   int64          `json:"total"`
}

type AdminEditUserRequest struct {
	Base
	NewPassword string `json:"new_password"`
	Domain      string `json:"domain"`
	IsAdmin     bool   `json:"is_admin"`
}
