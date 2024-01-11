package models

import "gorm.io/gorm"

type Article struct {
	ID        		   uint    `gorm:"primary key;autoIncrement" json:"id"`
	Author    		  *string `json:"author"`
	Title     		  *string `json:"title"`
	Date  	  		  *string `json:"date"`
	Description  	  *string `json:"description"`
	Image  	  		  *string `json:"image"`
}

func MigrateArticles(db *gorm.DB) error {
	err := db.AutoMigrate(&Article{})
	return err
}