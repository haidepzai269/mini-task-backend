package main

import (
	"net/http"

	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Giữ nguyên Struct Task và User như bản cũ
type Task struct {
	ID          string `json:"id" gorm:"primaryKey"`
	Title       string `json:"title"`
	Deadline    string `json:"deadline"`
	Status      bool   `json:"status"`
	Priority    string `json:"priority"`
	CompletedAt string `json:"completed_at"`
	Owner       string `json:"owner" gorm:"index"`
}

type User struct {
	Username string `json:"username" gorm:"primaryKey"`
	Password string `json:"password"`
}

var DB *gorm.DB
var jwtKey = []byte("hai_dep_zai_secret_key") // Trong thực tế nên để vào file .env

// Hàm băm mật khẩu
func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

// Hàm kiểm tra mật khẩu
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Vui lòng đăng nhập"})
			c.Abort()
			return
		}

		claims := jwt.MapClaims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Phiên đăng nhập hết hạn"})
			c.Abort()
			return
		}

		// SỬA TẠI ĐÂY: Lấy username từ Token và lưu vào Context của Gin
		// claims["username"] tương ứng với cái bạn đã tạo ở hàm Login
		c.Set("currentUser", claims["username"]) 
		
		c.Next()
	}
}


// Kết nối Database
// Kết nối Database
func initDB() {
	// Đã sửa: Tách dsn và var err error ra hai dòng riêng biệt
	dsn := "postgresql://neondb_owner:npg_vbdxul3VUm1A@ep-restless-frog-a19t12xv-pooler.ap-southeast-1.aws.neon.tech/neondb?sslmode=require"
	var err error
	
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic("Không thể kết nối Database!")
	}

	// Tự động tạo bảng dựa trên struct
	DB.AutoMigrate(&User{}, &Task{})
}

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}

func main() {
	initDB() // Khởi tạo kết nối khi chạy app

	r := gin.Default()
	r.Use(CORSMiddleware()) // Giữ nguyên CORS để React có thể gọi API

	// --- AUTH ROUTES ---
	
	// 1. Đăng ký: Cần băm (hash) mật khẩu trước khi lưu vào DB
	r.POST("/register", func(c *gin.Context) {
		var user User
		if err := c.ShouldBindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Dữ liệu không hợp lệ"})
			return
		}

		// Sử dụng hàm HashPassword đã khai báo để mã hóa mật khẩu
		hashedPassword, err := HashPassword(user.Password)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Không thể mã hóa mật khẩu"})
			return
		}
		user.Password = hashedPassword // Gán mật khẩu đã mã hóa vào struct

		if err := DB.Create(&user).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Tên đăng nhập đã tồn tại"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"message": "Đăng ký thành công!"})
	})

	// 2. Đăng nhập: Kiểm tra mật khẩu băm và trả về JWT Token
	r.POST("/login", func(c *gin.Context) {
		var loginData User
		var user User
		c.ShouldBindJSON(&loginData)
		
		// Tìm user trong DB theo Username
		result := DB.Where("username = ?", loginData.Username).First(&user)
		if result.Error != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Tài khoản không tồn tại"})
			return
		}

		// Sử dụng hàm CheckPasswordHash để so sánh mật khẩu nhập vào với mật khẩu đã mã hóa trong DB
		if !CheckPasswordHash(loginData.Password, user.Password) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Sai mật khẩu"})
			return
		}

		// Tạo JWT Token (Hết hạn sau 24 giờ)
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"username": user.Username,
			"exp":      time.Now().Add(time.Hour * 24).Unix(),
		})

		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Không thể tạo mã đăng nhập"})
			return
		}

		// Trả về Token và Username cho Frontend lưu trữ
		c.JSON(http.StatusOK, gin.H{
			"message": "Đăng nhập thành công",
			"token":   tokenString,
			"user":    user.Username,
		})
	})

	// --- TASK ROUTES (BẢO VỆ BỞI JWT) ---
	
	// Tạo một Group để áp dụng AuthMiddleware cho tất cả các thao tác với Task
// --- TASK ROUTES (ĐÃ LỌC THEO NGƯỜI DÙNG) ---
authorized := r.Group("/")
authorized.Use(AuthMiddleware()) 
{
    // 1. Lấy danh sách task: Chỉ lấy những task của chính người đang đăng nhập
    authorized.GET("/tasks", func(c *gin.Context) {
        // Lấy username đã được Middleware lưu vào context
        username, _ := c.Get("currentUser") 
        
        var tasks []Task
        // Thêm điều kiện Where để chỉ tìm các task có owner là username này
        DB.Where("owner = ?", username).Find(&tasks)
        c.JSON(http.StatusOK, tasks)
    })

    // 2. Tạo task mới: Phải gắn tên người tạo vào cột Owner
    authorized.POST("/tasks", func(c *gin.Context) {
        username, _ := c.Get("currentUser")
        
        var newTask Task
        if err := c.ShouldBindJSON(&newTask); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "Dữ liệu không hợp lệ"})
            return
        }
        
        // Gán chủ sở hữu cho task trước khi lưu vào database
        newTask.Owner = username.(string)
        
        DB.Create(&newTask)
        c.JSON(http.StatusOK, newTask)
    })

    // 3. Cập nhật task: Kiểm tra đúng ID và đúng chủ sở hữu
    authorized.PUT("/tasks/:id", func(c *gin.Context) {
        id := c.Param("id")
        username, _ := c.Get("currentUser")
        
        var task Task
        // Chỉ tìm task nếu nó khớp cả ID và Owner
        if err := DB.First(&task, "id = ? AND owner = ?", id, username).Error; err != nil {
            c.JSON(http.StatusNotFound, gin.H{"message": "Không tìm thấy task hoặc bạn không có quyền sửa"})
            return
        }
        
        c.ShouldBindJSON(&task)
        DB.Save(&task)
        c.JSON(http.StatusOK, task)
    })

    // 4. Xóa task: Chỉ xóa nếu đúng chủ sở hữu
    authorized.DELETE("/tasks/:id", func(c *gin.Context) {
        id := c.Param("id")
        username, _ := c.Get("currentUser")
        
        // Thêm điều kiện owner vào lệnh Delete để đảm bảo không xóa nhầm task của người khác
        result := DB.Delete(&Task{}, "id = ? AND owner = ?", id, username)
        
        if result.RowsAffected == 0 {
            c.JSON(http.StatusNotFound, gin.H{"message": "Không tìm thấy task để xóa"})
            return
        }
        
        c.JSON(http.StatusOK, gin.H{"message": "Đã xóa thành công"})
    })

	authorized.PUT("/user/update", func(c *gin.Context) {
		oldUsername, _ := c.Get("currentUser")
		var updateData struct {
			NewUsername string `json:"new_username"`
			NewPassword string `json:"new_password"`
		}
		
		if err := c.ShouldBindJSON(&updateData); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Dữ liệu không hợp lệ"})
			return
		}
	
		var user User
		if err := DB.First(&user, "username = ?", oldUsername).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "Không tìm thấy người dùng"})
			return
		}
	
		// Cập nhật tên nếu có
		if updateData.NewUsername != "" {
			// Lưu ý: Đổi Primary Key cần cẩn thận, nhưng với quy mô này ta có thể cập nhật trực tiếp
			user.Username = updateData.NewUsername
		}
	
		// Cập nhật mật khẩu nếu có (phải băm lại)
		if updateData.NewPassword != "" {
			hashed, _ := HashPassword(updateData.NewPassword)
			user.Password = hashed
		}
	
		if err := DB.Save(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Không thể cập nhật thông tin"})
			return
		}
	
		c.JSON(http.StatusOK, gin.H{"message": "Cập nhật thành công! Vui lòng đăng nhập lại."})
	})
}



port := os.Getenv("PORT")
    if port == "" {
        port = "8080"
    }
    r.Run(":" + port)
}