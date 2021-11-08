package main

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/Trirandom/basic-listener/pkg/apitools"
	"github.com/Trirandom/capstone-server/pkg/mongo"

	jwt "github.com/appleboy/gin-jwt"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"gopkg.in/mgo.v2/bson"
)

type EntryDto struct {
	DataString string `form:"dataString" json:"dataString" binding:"required"`
	Key        string `form:"key" json:"key" binding:"required"`
}

type Entry struct {
	DataString string `json:"data" binding:"required"`
	Date       string `json:"key" binding:"required"`
}

var identityKey = "id"

func registerHandler(c *gin.Context) {
	var entry EntryDto
	if err := c.ShouldBind(&entry); err != nil {
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}
	ms, err := mongo.NewSession()
	if err != nil {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{
			"status":     http.StatusInternalServerError,
			"message":    "Unable to open a mongo session",
			"resourceId": entry.DataString,
		})
		return
	}

	var row []Entry = nil
	ms.GetCollection("entries").Find(bson.M{"dataString": entry.DataString}).All(&row)
	if row != nil {
		defer ms.Close()
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{
			"status":     http.StatusConflict,
			"message":    "Already exist",
			"resourceId": entry.DataString,
		})
		return
	}

	dbEntry := Entry{
		DataString: entry.DataString,
	}
	err = ms.GetCollection("entries").Insert(dbEntry)
	if err != nil {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"status":     http.StatusInternalServerError,
			"message":    "Cannot insert into database",
			"resourceId": entry.DataString,
		})
		return
	} else {
		c.JSON(http.StatusCreated, gin.H{
			"status":     http.StatusCreated,
			"message":    "Entry created",
			"resourceId": entry.DataString,
		})
	}
	defer ms.Close()
	return
}

func main() {
	port := os.Getenv("PORT")
	r := gin.New()
	r.Use(cors.New(cors.Config{
		AllowMethods:     []string{"POST"},
		AllowHeaders:     []string{"Origin, X-Requested-With, Content-Type, Accept, Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		AllowAllOrigins:  true,
		MaxAge:           12 * time.Hour,
	}))
	r.Use(gin.Logger())
	r.Use(gin.Recovery())
	if port == "" {
		port = "8080"
	}
	// the jwt middleware
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "test zone",
		Key:         []byte(apitools.GoDotEnvVariable("MIDDLEWARE_KEY")),
		Timeout:     time.Hour,
		MaxRefresh:  time.Hour,
		IdentityKey: identityKey,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			return nil
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			return nil
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			return nil, nil
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			// fmt.Println("Authorizator data ", data.(*User).FirstName)
			// if v, ok := data.(*User); ok && v.FirstName == "admin" {
			// 	fmt.Println("Authorizator v  %#v", v.FirstName)
			// 	return true
			// }
			// fmt.Println("Authorizator failed v  %#v", data.(*User))
			return true
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"status":  code,
				"message": message,
			})
		},
		// TokenLookup is a string in the form of "<source>:<name>" that is used
		// to extract token from the request.
		// Optional. Default value "header:Authorization".
		// Possible values:
		// - "header:<name>"
		// - "query:<name>"
		// - "cookie:<name>"
		// - "param:<name>"
		TokenLookup: "header: Authorization, query: token, cookie: jwt",
		// TokenLookup: "query:token",
		// TokenLookup: "cookie:token",

		// TokenHeadName is a string in the header. Default value is "Bearer"
		TokenHeadName: "Bearer",

		// TimeFunc provides the current time. You can override it to use another time value. This is useful for testing or if your server uses a different time zone than your tokens.
		TimeFunc: time.Now,
	})

	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	r.POST("/register", registerHandler)

	r.NoRoute(authMiddleware.MiddlewareFunc(), func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		log.Printf("NoRoute claims: %#v \n", claims)
		c.JSON(http.StatusNotFound, gin.H{
			"status":  http.StatusNotFound,
			"message": "Page not found",
		})
	})

	if err := http.ListenAndServe(":"+port, r); err != nil {
		log.Fatal(err)
	}
}
