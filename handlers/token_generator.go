package handlers

import (
	"fmt"
	"errors"
	"strings"

    "github.com/dgrijalva/jwt-go"
    "github.com/nafla/be-go-fiber/models"
	"github.com/gofiber/fiber/v2"
)

type UserInfo struct {
    ID   uint   `json:"id"`
    Name string `json:"name"`
}

func GenerateToken(user *models.User) (string, error) {
    // Set claims (klaim) token
    claims := jwt.MapClaims{
        "ID":       user.ID,
        "Username": user.Username,
        "Name":     user.FullName,
    }

    // Membuat token dengan claims
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

    // Menandatangani token dengan secret key
    signedToken, err := token.SignedString([]byte("your_secret_key"))
    if err != nil {
        return "", fmt.Errorf("could not generate token: %v", err)
    }

    return signedToken, nil
}


func GetUserInfoFromToken(context *fiber.Ctx) (*UserInfo, error) {
    // Ambil token dari header Authorization
    authorizationHeader := context.Get("Authorization")
    if authorizationHeader == "" {
        return nil, errors.New("Missing Authorization header")
    }

    // Pastikan token dimulai dengan "Bearer "
    if !strings.HasPrefix(authorizationHeader, "Bearer ") {
        return nil, errors.New("Invalid token format")
    }

    // Ambil token setelah awalan "Bearer "
    token := strings.TrimPrefix(authorizationHeader, "Bearer ")
    fmt.Println("Received Token:", token)

    // Implementasi validasi token
    claims := jwt.MapClaims{}
    _, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
        return []byte("your_secret_key"), nil
    })

    // Handle jika parsing token gagal
    if err != nil {
        return nil, errors.New("Invalid token")
    }

    // Pastikan "Name" claim ada dan konversi ke string
    nameClaim, ok := claims["Name"].(string)
    if !ok {
        return nil, errors.New("Invalid or missing 'Name' claim in token")
    }

    // Ambil nilai klaim yang diperlukan
    userID, ok := claims["ID"].(float64)
    if !ok {
        return nil, errors.New("Invalid user ID in token")
    }

    // Deklarasikan dan isi nilai userInfo
    userInfo := &UserInfo{
        ID:   uint(userID),
        Name: nameClaim,
    }

    return userInfo, nil
}



