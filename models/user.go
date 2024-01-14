package models

import "gorm.io/gorm"

type User struct {
    gorm.Model
    FullName string   `gorm:"column:full_name" json:"fullName"`
    Address  string   `json:"address"`
    Username string   `json:"username"`
    Gender   string   `json:"gender"`
    Password string   `json:"password"`
    Role     string   `json:"role"`
    Articles []Article `json:"articles" gorm:"foreignKey:UserID"`
}

func MigrateUsers(db *gorm.DB) error {
    err := db.AutoMigrate(&User{})
    return err
}

func FindUserByUsernameAndPassword(db *gorm.DB, username, password string) (*User, error) {
    user := &User{}
    err := db.Preload("Articles").Where("username = ?", username).First(user).Error
    if err != nil {
        return nil, err
    }

    return user, nil
}
