package models

import (
	"gorm.io/gorm"
)

type Paslon struct {
	gorm.Model
	No               int    `json:"no"`
	Name             string `json:"name"`
	VisionAndMission string `json:"visionAndMission"`
	Picture          string `json:"picture"`
	Vote             []Vote `json:"vote" gorm:"foreignKey:PaslonID"`
	Partai           []Partai `json:"partai" gorm:"foreignKey:PaslonID"`
}

func MigratePaslon(db *gorm.DB) error {
    return db.AutoMigrate(&Paslon{})
}