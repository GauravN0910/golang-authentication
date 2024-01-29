package routes

import(
	"github.com/gin-gonic/gin"
	"github.com/GauravN0910/golang-authentication/middleware"
	controller "github.com/GauravN0910/golang-authentication/controllers"
)


func UserRoutes(incomingRoutes *gin.Engine){
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controller.GetUsers())
	incomingRoutes.GET("/users/:user_id", controller.GetUserByID())	
}
