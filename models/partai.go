package models

import (
	"gorm.io/gorm"
)

type Partai struct {
	gorm.Model
	Name             string `json:"name"`
	Chairman         string `json:"chairman"`
	VisionAndMission string `json:"visionAndMission"`
	Address          string `json:"address"`
	Picture          string `json:"picture"`
	PaslonID         uint   `json:"-"`
	Paslon           Paslon `json:"paslon" gorm:"foreignKey:PaslonID"`
}

func MigratePartai(db *gorm.DB) error {
    return db.AutoMigrate(&Partai{})
}