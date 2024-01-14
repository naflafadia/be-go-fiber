package models

import "gorm.io/gorm"

type Article struct {
    gorm.Model
    Author      string   `json:"author"`
    Title       string   `json:"title"`
    Date        string   `json:"date"`
    Description string   `json:"description"`
    Picture     string   `json:"picture"`
    UserID      uint     `json:"-"`
    User        User     `json:"user" gorm:"foreignKey:UserID"`
}

func MigrateArticles(db *gorm.DB) error {
    err := db.AutoMigrate(&Article{})
    return err
}
