package main

import (
	
	"log"
	"net/http"
	"os"

	"github.com/nafla/be-go-fiber/models"
	"github.com/nafla/be-go-fiber/storage"
	"github.com/gofiber/fiber/v2"
	"github.com/joho/godotenv"
	"gorm.io/gorm"
)

type Article struct {
	Author    		  string `json:"author"`
	Title     		  string `json:"title"`
	Date 	  		  string `json:"date"`
	Description 	  string `json:"description"`
	Image 	  		  string `json:"image"`
}

type Repository struct {
	DB *gorm.DB
}

func (r *Repository) CreateArticle(context *fiber.Ctx) error {
	article := Article{}

	err := context.BodyParser(&article)

	if err != nil {
		context.Status(http.StatusUnprocessableEntity).JSON(
			&fiber.Map{"message": "request failed"})
		return err
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

	err := r.DB.Find(articleModels).Error
	if err != nil {
		context.Status(http.StatusBadRequest).JSON(
			&fiber.Map{"message": "could not get articles"})
		return err
	}

	context.Status(http.StatusOK).JSON(&fiber.Map{
		"message": "articles fetched successfully",
		"data":    articleModels,
	})
	return nil
}

func (r *Repository) SetupRoutes(app *fiber.App) {
	api := app.Group("/api")
	api.Get("/articles", r.GetArticles)
	api.Post("/article", r.CreateArticle)
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
		log.Fatal("could not migrate db")
	}

	r := Repository{
		DB: db,
	}
	app := fiber.New()
	r.SetupRoutes(app)
	app.Listen(":8080")
}