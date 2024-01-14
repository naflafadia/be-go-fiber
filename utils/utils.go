package main

import (
    "errors"
    "github.com/gofiber/fiber/v2"
)

type UserInfo struct {
    ID   uint   `json:"id"`
    Name string `json:"name"`
}

func GetUserInfoFromToken(context *fiber.Ctx) (*UserInfo, error) {
    token := context.Get("Authorization")

    if token != "valid_token" {
        return nil, errors.New("Invalid token")
    }

    userInfo := &UserInfo{
        ID:   1,
        Name: "John Doe",
    }

    return userInfo, nil
}
