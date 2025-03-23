package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	"github.com/rs/cors"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

type User struct {
	ID       int    `json:"id"` //уникальное поле
	Username string `json:"username"` //уникальное поле
	Phone    string `json:"phone"` //уникальное поле
	Name     string `json:"name"`
	Lastname string `json:"lastname"`
	Password string `json:"password"`
	Icons    string `json:"icons"`
}

var (
	jwtKey          = []byte("my_familly_db")
	refreshTokenKey = []byte("my_familly_db_refresh")
)

type Claims struct {
	Phone string `json:"phone"`
	jwt.StandardClaims
}

// Ошибка в формате JSON
func writeError(w http.ResponseWriter, message string, status int) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"result": message})
}

// Подключение к базе данных
func initDB() {
	var err error
	connStr := "user=georgijantonevic dbname=georgijantonevic sslmode=disable" // Укажите свои данные подключения
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
}

// Генерация accessToken
func generateAccessToken(phone string) (string, error) {
	expirationTime := time.Now().Add(1 * time.Minute) // Access token действителен 15 минут
	claims := &Claims{
		Phone: phone,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtKey)
}

// Генерация refreshToken
func generateRefreshToken(phone string) (string, error) {
	expirationTime := time.Now().Add(7 * 24 * time.Hour) // Refresh token действителен 7 дней
	claims := &Claims{
		Phone: phone,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(refreshTokenKey)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	user.Icons = "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcQ_I16T09X0dNr853Bc9X4zAFh6rCKnvan39Q&s"

	// Проверка на уникальность Username
	var existingUserUsername string
	err = db.QueryRow("SELECT username FROM users WHERE username=$1", user.Username).Scan(&existingUserUsername)
	if err == nil {
		writeError(w, "Пользователь с никнеймом "+user.Username+" уже существует", http.StatusConflict)
		return
	}

	// Проверка на уникальность Phone
	var existingUserPhone string
	err = db.QueryRow("SELECT phone FROM users WHERE phone=$1", user.Phone).Scan(&existingUserPhone)
	if err == nil {
		writeError(w, "Пользователь с номером телефона "+user.Phone+" уже существует", http.StatusConflict)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	_, err = db.Exec(
		"INSERT INTO users (username, phone, name, lastname, password, icons) VALUES ($1, $2, $3, $4, $5, $6)",
		user.Username, user.Phone, user.Name, user.Lastname, hashedPassword, user.Icons,
	)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Успешная регистрация
	w.WriteHeader(http.StatusOK)                                                           // Устанавливаем статус 200 OK
	w.Header().Set("Content-Type", "application/json")                                     // Устанавливаем заголовок Content-Type
	json.NewEncoder(w).Encode(map[string]string{"message": "Регистрация прошла успешно!"}) // Отправляем сообщение
}

// Авторизация пользователя
func loginHandler(w http.ResponseWriter, r *http.Request) {
	var user User
	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var storedPassword string
	err = db.QueryRow("SELECT password FROM users WHERE phone=$1", user.Phone).Scan(&storedPassword)
	if err != nil {
		writeError(w, "Логин или пароль не совпадают", http.StatusUnauthorized)
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(user.Password))
	if err != nil {
		writeError(w, "Логин или пароль не совпадают", http.StatusUnauthorized)
		return
	}

	// Генерация токенов
	accessToken, err := generateAccessToken(user.Phone)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	refreshToken, err := generateRefreshToken(user.Phone)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Установка refreshToken в куки
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    refreshToken,
		Path:     "/",
		HttpOnly: true,
		// Secure:   true, // Используйте true, если у вас HTTPS
		SameSite: http.SameSiteStrictMode,
	})

	response := map[string]string{
		"access_token": accessToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK) // 200 OK
	json.NewEncoder(w).Encode(response)
}

// Middleware для проверки токена
func validateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("Authorization")
		if tokenString == "" {
			writeError(w, "Missing authorization header", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})
		if err != nil || !token.Valid {
			writeError(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Обновление токенов
func refreshHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("refresh_token")
	if err != nil || cookie == nil {
		writeError(w, "Refresh token отсутствует", http.StatusUnauthorized)
		return
	}

	refreshToken := cookie.Value

	var claims Claims
	tkn, err := jwt.ParseWithClaims(refreshToken, &claims, func(token *jwt.Token) (interface{}, error) {
		return refreshTokenKey, nil
	})

	if err != nil || !tkn.Valid {
		writeError(w, "Неверный refresh token", http.StatusUnauthorized)
		return
	}

	newAccessToken, err := generateAccessToken(claims.Phone)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	newRefreshToken, err := generateRefreshToken(claims.Phone)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    newRefreshToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	})

	response := map[string]string{
		"access_token": newAccessToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Поиск пользователей по username
func searchUsersHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	limit := r.URL.Query().Get("limit")
	offset := r.URL.Query().Get("offset")

	query := "SELECT id, username, phone, name, lastname, icons FROM users WHERE username ILIKE $1"
	args := []interface{}{fmt.Sprintf("%%%s%%", username)} // Используем ILIKE для нечувствительного поиска

	if limit != "" {
		query += " LIMIT $2"
		args = append(args, limit)
	}
	if offset != "" {
		query += " OFFSET $3"
		args = append(args, offset)
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Username, &user.Phone, &user.Name, &user.Lastname, &user.Icons); err != nil {
			writeError(w, err.Error(), http.StatusInternalServerError)
			return
		}
		users = append(users, user)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(users)
}

// Обработчик для получения профиля пользователя
func profileHandler(w http.ResponseWriter, r *http.Request) {
	// Извлекаем токен из заголовка Authorization
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		writeError(w, "Missing authorization header", http.StatusUnauthorized)
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		writeError(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	// Извлекаем телефон из токена
	phone := claims.Phone

	// Запрос к базе данных для получения информации о пользователе
	var user User
	err = db.QueryRow("SELECT id, username, phone, name, lastname, icons FROM users WHERE phone=$1", phone).Scan(&user.ID, &user.Username, &user.Phone, &user.Name, &user.Lastname, &user.Icons)
	if err != nil {
		writeError(w, "User not found", http.StatusNotFound)
		return
	}

	// Возвращаем данные о пользователе в формате JSON
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Удаление refresh_token из куки
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1, // Устанавливаем MaxAge в -1 для удаления куки
		SameSite: http.SameSiteStrictMode,
	})

	// Успешный разлогин
	w.WriteHeader(http.StatusOK)                                                         // Устанавливаем статус 200 OK
	w.Header().Set("Content-Type", "application/json")                                   // Устанавливаем заголовок Content-Type
	json.NewEncoder(w).Encode(map[string]string{"message": "Вы успешно разлогинились!"}) // Отправляем сообщение
}

// Функция для обновления имени и фамилии пользователя
func updateNameHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		writeError(w, "Отсутствует заголовок авторизации", http.StatusUnauthorized)
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		writeError(w, "Неверный токен", http.StatusUnauthorized)
		return
	}

	phone := claims.Phone

	var updatedUser User
	err = json.NewDecoder(r.Body).Decode(&updatedUser)
	if err != nil || updatedUser.Name == "" || updatedUser.Lastname == "" {
		writeError(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("UPDATE users SET name=$1, lastname=$2 WHERE phone=$3", updatedUser.Name, updatedUser.Lastname, phone)
	if err != nil {
		writeError(w, "Ошибка обновления имени и фамилии", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "успешно!"})
}

// Функция для обновления номера телефона пользователя
func updatePhoneHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		writeError(w, "Отсутствует заголовок авторизации", http.StatusUnauthorized)
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		writeError(w, "Неверный токен", http.StatusUnauthorized)
		return
	}

	oldPhone := claims.Phone

	var updatedUser User
	err = json.NewDecoder(r.Body).Decode(&updatedUser)
	if err != nil || updatedUser.Phone == "" {
		writeError(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	// Проверка уникальности номера телефона
	var existingPhone string
	err = db.QueryRow("SELECT phone FROM users WHERE phone=$1", updatedUser.Phone).Scan(&existingPhone)
	if err == nil && existingPhone != updatedUser.Phone {
		writeError(w, "Такой номер телефона уже зарегистрирован", http.StatusConflict)
		return
	} else if err != sql.ErrNoRows {
		writeError(w, "Ошибка базы данных", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("UPDATE users SET phone=$1 WHERE phone=$2", updatedUser.Phone, oldPhone)
	if err != nil {
		writeError(w, "Ошибка обновления номера телефона", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "успешно!"})
}

// Функция для обновления юзернейма пользователя
func updateUsernameHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		writeError(w, "Отсутствует заголовок авторизации", http.StatusUnauthorized)
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		writeError(w, "Неверный токен", http.StatusUnauthorized)
		return
	}

	phone := claims.Phone

	var updatedUser User
	err = json.NewDecoder(r.Body).Decode(&updatedUser)
	if err != nil || updatedUser.Username == "" {
		writeError(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	// Проверка уникальности юзернейма
	var existingUsername string
	err = db.QueryRow("SELECT username FROM users WHERE username=$1", updatedUser.Username).Scan(&existingUsername)

	// Если ошибка не равна sql.ErrNoRows и юзернейм существует, возвращаем конфликт
	if err == nil && existingUsername != updatedUser.Username {
		writeError(w, "Такой юзернейм уже существует", http.StatusConflict)
		return
	} else if err != sql.ErrNoRows && err != nil {
		writeError(w, "Ошибка базы данных", http.StatusInternalServerError)
		return
	}

	// Обновление юзернейма в базе данных
	_, err = db.Exec("UPDATE users SET username=$1 WHERE phone=$2", updatedUser.Username, phone)
	if err != nil {
		writeError(w, "Ошибка обновления юзернейма", http.StatusInternalServerError)
		return
	}

	// Успешный ответ
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Юзернейм успешно обновлен!"})
}

// Функция для обновления ссылки на аватар пользователя
func updateIconsHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		writeError(w, "Отсутствует заголовок авторизации", http.StatusUnauthorized)
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		writeError(w, "Неверный токен", http.StatusUnauthorized)
		return
	}

	phone := claims.Phone

	var updatedUser User
	err = json.NewDecoder(r.Body).Decode(&updatedUser)
	if err != nil || updatedUser.Icons == "" {
		writeError(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	_, err = db.Exec("UPDATE users SET icons=$1 WHERE phone=$2", updatedUser.Icons, phone)
	if err != nil {
		writeError(w, "Ошибка обновления ссылки на аватар", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "успешно!"})
}

// Функция для обновления пароля пользователя
func updatePasswordHandler(w http.ResponseWriter, r *http.Request) {
	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		writeError(w, "Отсутствует заголовок авторизации", http.StatusUnauthorized)
		return
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if err != nil || !token.Valid {
		writeError(w, "Неверный токен", http.StatusUnauthorized)
		return
	}

	phone := claims.Phone

	var updatedUser User
	err = json.NewDecoder(r.Body).Decode(&updatedUser)
	if err != nil || updatedUser.Password == "" {
		writeError(w, "Неверный формат запроса", http.StatusBadRequest)
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(updatedUser.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, "Ошибка хеширования пароля", http.StatusInternalServerError)
		return
	}

	_, err = db.Exec("UPDATE users SET password=$1 WHERE phone=$2", hashedPassword, phone)
	if err != nil {
		writeError(w, "Ошибка обновления пароля", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "успешно!"})
}

// WEBSOCKETS
// Структура для хранения соединения и идентификатора пользователя
type Client struct {
	conn   *websocket.Conn
	userID string
	name   string
}

// Структура для отправляемого сообщения
type Message struct {
	UserID    string `json:"user_id"`
	Name      string `json:"name"`
	Content   string `json:"content"`
	Timestamp string `json:"timestamp"`
	ToUserID  string `json:"toUserID"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true // Разрешаем все источники (не рекомендуется в продакшене)
	},
}

var clients = make(map[string]*Client) // Подключенные клиенты по userID

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Ошибка при подключении WebSocket:", err)
		return
	}
	defer conn.Close()

	var client *Client

	for {
		var msg Message
		// Читаем сообщение в формате JSON
		if err := conn.ReadJSON(&msg); err != nil {
			log.Println("Ошибка при чтении сообщения:", err)
			break
		}

		// Если клиент еще не был зарегистрирован, создаем его
		if client == nil {
			client = &Client{conn: conn, userID: msg.UserID, name: msg.Name}
			clients[msg.UserID] = client
			defer delete(clients, msg.UserID) // Удаляем клиента при выходе
		}

		message := Message{
			UserID:    client.userID,
			Name:      client.name,
			Timestamp: time.Now().Format(time.RFC3339), // Текущее время в формате RFC3339
			Content:   msg.Content,
			ToUserID:  msg.ToUserID, // Используем toUserId из пришедшего сообщения
		}

		// Отправляем сообщение только собеседнику
		if recipient, ok := clients[message.ToUserID]; ok {
			if err := recipient.conn.WriteJSON(message); err != nil {
				log.Println("Ошибка при отправке сообщения:", err)
				recipient.conn.Close()
				delete(clients, message.ToUserID)
			}
		} else {
			log.Printf("Пользователь с ID %s не найден\n", message.ToUserID)
		}
	}
}

func main() {
	initDB()
	defer db.Close()

	r := mux.NewRouter()
	r.HandleFunc("/register", registerHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	r.HandleFunc("/refresh", refreshHandler).Methods("POST")
	r.Handle("/search", validateToken(http.HandlerFunc(searchUsersHandler))).Methods("GET")
	r.Handle("/profile", validateToken(http.HandlerFunc(profileHandler)))
	r.Handle("/profile/update/name", validateToken(http.HandlerFunc(updateNameHandler))).Methods("PATCH")
	r.Handle("/profile/update/phone", validateToken(http.HandlerFunc(updatePhoneHandler))).Methods("PATCH")
	r.Handle("/profile/update/username", validateToken(http.HandlerFunc(updateUsernameHandler))).Methods("PATCH")
	r.Handle("/profile/update/icons", validateToken(http.HandlerFunc(updateIconsHandler))).Methods("PATCH")
	r.Handle("/profile/update/password", validateToken(http.HandlerFunc(updatePasswordHandler))).Methods("PATCH")
	r.HandleFunc("/logout", logoutHandler).Methods("POST")

	// Добавляем маршрут для WebSocket
	r.HandleFunc("/ws", handleWebSocket)

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:5173"},
		AllowCredentials: true,
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "PATCH"},
	})

	fmt.Println("Сервер запущен на :8080")
	log.Fatal(http.ListenAndServe(":8080", c.Handler(r)))
}
