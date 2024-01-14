package models

import "gorm.io/gorm"

type Vote struct {
	gorm.Model
	UserID   uint   `json:"-"`
	PaslonID uint   `json:"-"`
	User     User   `json:"user" gorm:"foreignKey:UserID"`
	Paslon   Paslon `json:"paslon" gorm:"foreignKey:PaslonID"`
}

func MigrateVotes(db *gorm.DB) error {
	err := db.AutoMigrate(&Vote{})
	return err
}
