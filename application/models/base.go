package models

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type Base struct {
	UUID uuid.UUID `gorm:"unique;not null"`
}

func (b *Base) BeforeCreate(tx *gorm.DB) (err error) {
	b.UUID = uuid.New()
	return
}
