package components

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/smtp"
	"os"

	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
)

func WriteJSON(w http.ResponseWriter, status int, v any) {

	w.Header().Set(`Content-Type`, `application/json`)
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)

}

type Server struct {
	listenAddr string
	store      Storage
}

type serverError struct {
	Error string `json:"error"`
}

func NewServer(listenAddr string, store Storage) *Server {
	return &Server{
		listenAddr: listenAddr,
		store:      store,
	}
}

func (s *Server) Run() {
	router := mux.NewRouter()
	router.HandleFunc("/register", s.handleregister)
	router.HandleFunc("/verify", s.handleVerification)
	router.HandleFunc("/test", s.handleTest)

	log.Println("JSON API server is running on port:", s.listenAddr)
	http.ListenAndServe(s.listenAddr, router)

}

func (s *Server) handleTest(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, "Server is running")
}

func (s *Server) handleregister(w http.ResponseWriter, r *http.Request) {

	var newuser NewUserRequest
	err := json.NewDecoder(r.Body).Decode(&newuser)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, err)
		log.Println(fmt.Errorf("not of correct formate"))
		return
	}
	existingUser, err := s.store.GetUserByEmail(newuser.Email)
	log.Println(err)
	if existingUser != nil {
		if ValidPassword(&newuser, existingUser) {
			if existingUser.Verified {
				WriteJSON(w, http.StatusOK, existingUser)
				return
			} else {
				err = s.EmailVerification(existingUser.Email, existingUser.ID)
				if err != nil {
					WriteJSON(w, http.StatusInternalServerError, serverError{Error: err.Error()})
					return
				}
				WriteJSON(w, http.StatusOK, "Email sent Successfully: Check your Email")
				return

			}
		} else {
			WriteJSON(w, http.StatusBadRequest, serverError{Error: "user is already registered log in using right credential"})
			return
		}
	}

	err = s.NewUserRegistration(newuser)
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError{Error: err.Error()})
		return
	}
	WriteJSON(w, http.StatusOK, "Email sent Successfully: Check your Email")
	return
}

func (s *Server) NewUserRegistration(newuser NewUserRequest) error {
	user, err := s.store.NewRegistraion(newuser)
	if err != nil {
		log.Println(fmt.Errorf("error occured"))
		return err
	}
	err = s.EmailVerification(newuser.Email, user.ID)
	if err != nil {
		return err
	}
	return nil
}

func (s *Server) EmailVerification(email string, userID uint64) error {
	token, err := GenerateToken()
	if err != nil {
		log.Println(fmt.Errorf("could not generate token"))
		return err
	}
	err = s.store.StoreInEmailVerification(userID, token)
	if err != nil {
		log.Println(fmt.Errorf("not able to store token"))
		return err
	}
	err = SendVerificationEmail(email, token)
	if err != nil {

		log.Println(fmt.Errorf("error in sending mail"))
		return err
	}
	return nil
}

func (s *Server) handleVerification(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		WriteJSON(w, http.StatusBadRequest, "token is required")
		return
	}
	err := s.store.VerifyToken(token)
	if err != nil {
		WriteJSON(w, http.StatusForbidden, err)
		return
	}
	WriteJSON(w, http.StatusOK, "Email verified successfully!")
}

func GenerateToken() (string, error) {
	token := make([]byte, 16)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}

func SendVerificationEmail(email, token string) error {
	err := godotenv.Load()
	if err != nil {
		return err
	}
	from := os.Getenv("emailID")
	// password := os.Getenv("apppassword")
	smtpHost := os.Getenv("smtpHost")
	smtpPort := os.Getenv("smtpPort")

	link := os.Getenv("link") + "/verify?token=" + token

	msg := "From: " + from + "\n" +
		"To: " + email + "\n" +
		"Subject: Email Verification\n\n" +
		"Click the link to verify your email: " + link

	auth := smtp.PlainAuth("", from, "ixckdotkcxkvisht", smtpHost)
	return smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{email}, []byte(msg))
}

func ValidPassword(newuser *NewUserRequest, user *User) bool {
	return bcrypt.CompareHashAndPassword([]byte(user.Encrypted_Password), []byte(newuser.Password)) == nil
}
