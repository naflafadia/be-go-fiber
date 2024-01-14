package main

import (
	"errors"
    "log"
    "net/http"
    "os"
	"fmt"
	"strings"

    "github.com/nafla/be-go-fiber/models"
    "github.com/nafla/be-go-fiber/storage"
     h "github.com/nafla/be-go-fiber/handlers"
	"github.com/dgrijalva/jwt-go"
    "github.com/gofiber/fiber/v2"
    "github.com/joho/godotenv"

    "gorm.io/gorm"
    "golang.org/x/crypto/bcrypt"
)

// Models
type ArticleInput struct {
    Author      string `json:"author"`
    Title       string `json:"title"`
    Date        string `json:"date"`
    Description string `json:"description"`
    Picture     string `json:"picture"`
}

type ArticleResponse struct {
    ID          uint        `json:"ID"`
    Author      UserInfo    `json:"author"`
    Title       string      `json:"title"`
    Date        string      `json:"date"`
    Description string      `json:"description"`
    Picture     string      `json:"picture"`
}

type UserInput struct {
    FullName string `json:"fullName"`
    Address  string `json:"address"`
    Username string `json:"username"`
    Gender   string `json:"gender"`
    Password string `json:"password"`
    Role     string `json:"role"`
}

type UserResponse struct {
    ID       uint   `json:"ID"`
    FullName string `json:"fullName"`
    Address  string `json:"address"`
    Username string `json:"username"`
    Gender   string `json:"gender"`
    Role     string `json:"role"`
}

type UserLoginInput struct {
    Username string `json:"username"`
    Password string `json:"password"`
}

type UserInfo struct {
    ID      uint   `json:"id"`
    Name    string `json:"name"`
    Address string `json:"address"` // Tambahkan baris ini
    // Tambahkan lebih banyak field sesuai kebutuhan.
}

type PartaiInput struct {
    Name             string `json:"name"`
    Chairman         string `json:"chairman"`
    VisionAndMission string `json:"visionAndMission"`
    Address          string `json:"address"`
    Picture          string `json:"picture"`
    PaslonID         uint   `json:"paslonID"`
}

type PaslonResponse struct {
    No               uint     `json:"no"`
    Name             string   `json:"name"`
    VisionAndMission string   `json:"visionAndMission"`
    Picture          string   `json:"picture"`
    PartaiNames      []string `json:"partaiNames,omitempty"`
}

type PartaiResponse struct {
    ID               uint   `json:"ID"`
    Name             string `json:"name"`
    Chairman         string `json:"chairman"`
    VisionAndMission string `json:"visionAndMission"`
    Address          string `json:"address"`
    Picture          string `json:"picture"`
    PaslonID         uint   `json:"paslonID"` // Tambahkan field PaslonID
}

type VoteInput struct {
	UserID   uint `json:"userID"`
	PaslonID uint `json:"paslonID"`
}

type Repository struct {
    DB *gorm.DB
}

// GetUserInfoFromToken mengembalikan informasi pengguna dari token otentikasi.
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

// Article
func (r *Repository) CreateArticle(context *fiber.Ctx) error {
    articleInput := ArticleInput{}

    err := context.BodyParser(&articleInput)
    if err != nil {
        context.Status(http.StatusUnprocessableEntity).JSON(
            &fiber.Map{"message": "request failed"})
        return err
    }

    // Mendapatkan informasi pengguna dari token otentikasi
    userFromToken, err := GetUserInfoFromToken(context)
    if err != nil {
        context.Status(http.StatusUnauthorized).JSON(
            &fiber.Map{"message": "unauthorized"})
        return nil
    }

    // Membuat objek artikel dengan menyertakan ID pengguna
    article := models.Article{
        Author:      articleInput.Author,
        Title:       articleInput.Title,
        Date:        articleInput.Date,
        Description: articleInput.Description,
        Picture:     articleInput.Picture,
        UserID:      userFromToken.ID,
    }

    err = r.DB.Create(&article).Error
    if err != nil {
        context.Status(http.StatusBadRequest).JSON(
            &fiber.Map{"message": "could not create article"})
        return err
    }

    context.Status(http.StatusOK).JSON(&fiber.Map{
        "message": "article has been added"})
    return nil
}

func (r *Repository) GetArticles(context *fiber.Ctx) error {
    articleModels := &[]models.Article{}

    // Mendapatkan informasi pengguna dari token otentikasi
    userFromToken, err := GetUserInfoFromToken(context)
    if err != nil {
        context.Status(http.StatusUnauthorized).JSON(
            &fiber.Map{"message": "unauthorized"})
        return nil
    }

    // Memuat artikel dengan relasi pengguna (User)
    err = r.DB.Preload("User", func(db *gorm.DB) *gorm.DB {
        return db.Select("ID, full_name")
    }).Find(articleModels).Error

    if err != nil {
        context.Status(http.StatusBadRequest).JSON(
            &fiber.Map{"message": "could not get articles"})
        return err
    }

    // Membuat slice ArticleResponse untuk menyimpan data artikel yang diformat
    var articleResponses []ArticleResponse

    // Mengisi articleResponses dengan data artikel yang diinginkan
    for _, article := range *articleModels {
        // Mengisi Author dengan informasi pengguna yang sedang login
        author := UserInfo{
            ID:   userFromToken.ID,
            Name: userFromToken.Name,
        }
    
        articleResponse := ArticleResponse{
            ID:          article.ID,
            Author:      author,
            Title:       article.Title,
            Date:        article.Date,
            Description: article.Description,
            Picture:     article.Picture,
        }
    
        articleResponses = append(articleResponses, articleResponse)
    }

    context.Status(http.StatusOK).JSON(&fiber.Map{
        "message": "articles fetched successfully",
        "data":    articleResponses,
    })
    return nil
}

// User
func (r *Repository) RegisterUser(context *fiber.Ctx) error {
    userInput := UserInput{}

    err := context.BodyParser(&userInput)
    if err != nil {
        context.Status(http.StatusUnprocessableEntity).JSON(
            &fiber.Map{"message": "request failed"})
        return err
    }

    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(userInput.Password), bcrypt.DefaultCost)
    if err != nil {
        context.Status(http.StatusInternalServerError).JSON(
            &fiber.Map{"message": "could not hash password"})
        return err
    }

    user := models.User{
        FullName: userInput.FullName,
        Address:  userInput.Address,
        Username: userInput.Username,
        Gender:   userInput.Gender,
        Password: string(hashedPassword),
        Role:     userInput.Role,
    }

    err = r.DB.Create(&user).Error
    if err != nil {
        context.Status(http.StatusBadRequest).JSON(
            &fiber.Map{"message": "could not register user"})
        return err
    }

    context.Status(http.StatusOK).JSON(&fiber.Map{
        "message": "user has been registered"})
    return nil
}

func (r *Repository) LoginUser(context *fiber.Ctx) error {
    userInput := UserLoginInput{}

    err := context.BodyParser(&userInput)
    if err != nil {
        context.Status(http.StatusUnprocessableEntity).JSON(
            &fiber.Map{"message": "request failed"})
        return err
    }

    user, err := models.FindUserByUsernameAndPassword(r.DB, userInput.Username, userInput.Password)
    if err != nil {
        context.Status(http.StatusUnauthorized).JSON(
            &fiber.Map{"message": "invalid credentials"})
        return err
    }

    // Setelah login berhasil, generate token
    token, err := h.GenerateToken(user)
    if err != nil {
        context.Status(http.StatusInternalServerError).JSON(
            &fiber.Map{"message": "could not generate token"})
        return err
    }

    // Mengirim token dan beberapa informasi pengguna ke klien
    context.Status(http.StatusOK).JSON(&fiber.Map{
        "message": "login successful",
        "token":   token,
        "username": user.Username,
    })
    return nil
}

func (r *Repository) GetUsers(context *fiber.Ctx) error {
    var users []models.User

    // Mendapatkan data pengguna dari database
    if err := r.DB.Find(&users).Error; err != nil {
        context.Status(http.StatusInternalServerError).JSON(
            &fiber.Map{"message": "could not get users"})
        return err
    }

    // Membuat slice UserResponse untuk menyimpan data pengguna yang diformat
    var userResponses []UserResponse

    // Mengisi userResponses dengan data pengguna yang diinginkan
    for _, user := range users {
        userResponse := UserResponse{
            ID:       user.ID,
            FullName: user.FullName,
            Address:  user.Address,
            Username: user.Username,
            Gender:   user.Gender,
            Role:     user.Role,
        }
        userResponses = append(userResponses, userResponse)
    }

    // Mengembalikan respons JSON yang diformat sesuai kebutuhan
    context.Status(http.StatusOK).JSON(&fiber.Map{
        "message": "users fetched successfully",
        "data":    userResponses,
    })
    return nil
}

// Paslon
func (r *Repository) CreatePaslon(context *fiber.Ctx) error {
    paslonInput := models.Paslon{}

    err := context.BodyParser(&paslonInput)
    if err != nil {
        context.Status(http.StatusUnprocessableEntity).JSON(
            &fiber.Map{"message": "request failed"})
        return err
    }

    response := r.DB.Create(&paslonInput)
    if response.Error != nil {
        context.Status(http.StatusBadRequest).JSON(
            &fiber.Map{"message": "could not create paslon"})
        return response.Error
    }

    // Membuat slice kosong untuk PartaiNames (dapat diisi sesuai kebutuhan)
    var partaiNames []string

    // Mengisi paslonResponses dengan data paslon yang diformat
    paslonResponse := PaslonResponse{
        No:               uint(paslonInput.No),
        Name:             paslonInput.Name,
        VisionAndMission: paslonInput.VisionAndMission,
        Picture:          paslonInput.Picture,
        PartaiNames:      partaiNames,
    }

    context.Status(http.StatusOK).JSON(&fiber.Map{
        "message": "paslon has been added",
        "data":    paslonResponse,
    })
    return nil
}


func (r *Repository) GetPaslons(context *fiber.Ctx) error {
    paslonModels := &[]models.Paslon{}

    err := r.DB.Preload("Partai").Preload("Partai").Find(paslonModels).Error

    if err != nil {
        context.Status(http.StatusBadRequest).JSON(
            &fiber.Map{"message": "could not get paslons"})
        return err
    }

    // Membuat slice PaslonResponse untuk menyimpan data paslon yang diformat
    var paslonResponses []PaslonResponse

    // Mengisi paslonResponses dengan data paslon yang diinginkan
    for _, paslon := range *paslonModels {
        // Mengisi partaiNames dengan nama partai yang memilih paslon
        partaiNames := r.getPartaiNames(paslon.ID)
    
        // Mengisi paslonResponses dengan data paslon yang diformat
        paslonResponse := PaslonResponse{
            No:               uint(paslon.No),
            Name:             paslon.Name,
            VisionAndMission: paslon.VisionAndMission,
            Picture:          paslon.Picture,
            PartaiNames:      partaiNames,
        }
    
        paslonResponses = append(paslonResponses, paslonResponse)
    }

    context.Status(http.StatusOK).JSON(&fiber.Map{
        "message": "paslons fetched successfully",
        "data":    paslonResponses,
    })
    return nil
}

// Partai
func (r *Repository) getPartaiNames(paslonID uint) []string {
    var partaiNames []string

    // Query untuk mendapatkan nama partai yang memilih paslon
    err := r.DB.Model(&models.Partai{}).
        Joins("JOIN votes ON partais.paslon_id = votes.paslon_id AND partais.user_id = votes.user_id").
        Joins("JOIN paslons ON votes.paslon_id = paslons.id").
        Where("paslons.id = ?", paslonID).
        Pluck("partais.name", &partaiNames)

    if err != nil {
        // Handle error dengan menampilkan log atau memberikan nilai default
        log.Println("Error fetching partai names:", err)
        return nil
    }

    return partaiNames
}

func (r *Repository) CreatePartai(context *fiber.Ctx) error {
    partaiInput := PartaiInput{}

    err := context.BodyParser(&partaiInput)
    if err != nil {
        context.Status(http.StatusUnprocessableEntity).JSON(
            &fiber.Map{"message": "request failed"})
        return err
    }

    // Pastikan paslon dengan ID yang diberikan ada di database
    var paslon models.Paslon
    if err := r.DB.First(&paslon, partaiInput.PaslonID).Error; err != nil {
        context.Status(http.StatusBadRequest).JSON(
            &fiber.Map{"message": "paslon not found"})
        return err
    }

    // Membuat objek partai dengan menyertakan Paslon
    partai := models.Partai{
        Name:             partaiInput.Name,
        Chairman:         partaiInput.Chairman,
        VisionAndMission: partaiInput.VisionAndMission,
        Address:          partaiInput.Address,
        Picture:          partaiInput.Picture,
        PaslonID:         paslon.ID,
    }

    response := r.DB.Create(&partai)
    if response.Error != nil {
        context.Status(http.StatusBadRequest).JSON(
            &fiber.Map{"message": "could not create partai"})
        return response.Error
    }

    context.Status(http.StatusOK).JSON(&fiber.Map{
        "message": "partai has been added",
        "data":    partai.ID, // Mengirim ID partai sebagai respons
    })
    return nil
}

func (r *Repository) GetPartais(context *fiber.Ctx) error {
    partaiModels := &[]models.Partai{}

    // Pastikan "Paslon" adalah nama relasi yang benar dalam model Partai
    err := r.DB.Preload("Paslon").Preload("Paslon").Find(partaiModels).Error

    if err != nil {
        context.Status(http.StatusBadRequest).JSON(
            &fiber.Map{"message": "could not get partais"})
        return err
    }

    // Membuat slice PartaiResponse untuk menyimpan data partai yang diformat
    var partaiResponses []PartaiResponse

    // Mengisi partaiResponses dengan data partai yang diinginkan
    for _, partai := range *partaiModels {
        // Mengisi partaiResponses dengan data partai yang diformat
        partaiResponse := PartaiResponse{
            ID:               partai.ID,
            Name:             partai.Name,
            Chairman:         partai.Chairman,
            VisionAndMission: partai.VisionAndMission,
            Address:          partai.Address,
            Picture:          partai.Picture,
            PaslonID:         partai.Paslon.ID,
        }

        partaiResponses = append(partaiResponses, partaiResponse)
    }

    context.Status(http.StatusOK).JSON(&fiber.Map{
        "message": "partais fetched successfully",
        "data":    partaiResponses,
    })
    return nil
}

// Vote
func (r *Repository) CreateVote(context *fiber.Ctx) error {
	voteInput := VoteInput{}

	err := context.BodyParser(&voteInput)
	if err != nil {
		context.Status(http.StatusUnprocessableEntity).JSON(
			&fiber.Map{"message": "request failed"})
		return err
	}

	// Pastikan userID dan paslonID valid
	var user models.User
	if err := r.DB.First(&user, voteInput.UserID).Error; err != nil {
		context.Status(http.StatusBadRequest).JSON(
			&fiber.Map{"message": "user not found"})
		return err
	}

	var paslon models.Paslon
	if err := r.DB.First(&paslon, voteInput.PaslonID).Error; err != nil {
		context.Status(http.StatusBadRequest).JSON(
			&fiber.Map{"message": "paslon not found"})
		return err
	}

	// Membuat objek vote dengan menyertakan User dan Paslon
	vote := models.Vote{
		UserID:   voteInput.UserID,
		PaslonID: voteInput.PaslonID,
		User:     user,
		Paslon:   paslon,
	}

	response := r.DB.Create(&vote)
	if response.Error != nil {
		context.Status(http.StatusBadRequest).JSON(
			&fiber.Map{"message": "could not create vote"})
		return response.Error
	}

	userFromToken, err := GetUserInfoFromToken(context)
	if err != nil {
		context.Status(http.StatusUnauthorized).JSON(
			&fiber.Map{"message": "unauthorized"})
		return nil
	}

	// Membuat peta respons
	responseMap := fiber.Map{
		"user": fiber.Map{
			"id":      userFromToken.ID,
			"fullName": userFromToken.Name,
			"address":  userFromToken.Address,
		},
		"paslonid": fiber.Map{
			"id":   vote.Paslon.ID,
			"name": vote.Paslon.Name,
		},
		"message": "vote has been added",
	}

	// Mengirim respons
	context.Status(http.StatusOK).JSON(responseMap)
	return nil
}

func (r *Repository) GetVotes(context *fiber.Ctx) error {
	voteModels := &[]models.Vote{}

	err := r.DB.Preload("User").Preload("Paslon").Find(voteModels).Error
	if err != nil {
		context.Status(http.StatusBadRequest).JSON(
			&fiber.Map{"message": "could not get votes"})
		return err
	}

	var formattedVotes []fiber.Map

    // Mengisi formattedVotes dengan data vote yang diinginkan
    for _, vote := range *voteModels {
        formattedVote := fiber.Map{
            "user": fiber.Map{
                "id":      vote.User.ID,
                "fullName": vote.User.FullName,
                "address":  vote.User.Address,
            },
            "paslonid": fiber.Map{
                "id":   vote.Paslon.ID,
                "name": vote.Paslon.Name,
            },
    }
    formattedVotes = append(formattedVotes, formattedVote)
    }

    // Format respons sesuai keinginan
    response := fiber.Map{
        "message": "votes fetched successfully",
        "data":    formattedVotes,
    }

    context.Status(http.StatusOK).JSON(response)

	return nil
}

// Router
func (r *Repository) SetupRoutes(app *fiber.App) {
    api := app.Group("/api")
    // Article
    api.Post("/article", r.CreateArticle)
    api.Get("/articles", r.GetArticles)
    // User
    api.Post("/register", r.RegisterUser)
    api.Post("/login", r.LoginUser)
	api.Get("/users", r.GetUsers)
    // Paslon
	api.Post("/paslon", r.CreatePaslon)
	api.Get("/paslons", r.GetPaslons)
    // Partai
	api.Post("/partai", r.CreatePartai)
	api.Get("/partais", r.GetPartais)
    // Vote
    api.Post("/vote", r.CreateVote) 
	api.Get("/votes", r.GetVotes)
}

func main() {
    err := godotenv.Load(".env")
    if err != nil {
        log.Fatal(err)
    }

    config := &storage.Config{
        Host:     os.Getenv("DB_HOST"),
        Port:     os.Getenv("DB_PORT"),
        Password: os.Getenv("DB_PASS"),
        User:     os.Getenv("DB_USER"),
        SSLMode:  os.Getenv("DB_SSLMODE"),
        DBName:   os.Getenv("DB_NAME"),
    }

    db, err := storage.NewConnection(config)
    if err != nil {
        log.Fatal("could not load the database")
    }

    err = models.MigrateArticles(db)
    if err != nil {
        log.Fatal("could not migrate articles table")
    }

    err = models.MigrateUsers(db)
    if err != nil {
        log.Fatal("could not migrate users table")
    }

    err = models.MigratePaslon(db)
    if err != nil {
    log.Fatal("could not migrate paslons table")
    }

    err = models.MigratePartai(db)
    if err != nil {
    log.Fatal("could not migrate partais table")
    }

    err = models.MigrateVotes(db)
    if err != nil {
        log.Fatal("could not migrate votes table")
    }

    r := Repository{
        DB: db,
    }
    app := fiber.New()
    r.SetupRoutes(app)
    app.Listen(":8080")
}
