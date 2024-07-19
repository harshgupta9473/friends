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
)

func WriteJSON(w http.ResponseWriter, status int, v any) {

	w.Header().Set(`Content-Type`, `application/json`)
	w.WriteHeader(status)
	err := json.NewEncoder(w).Encode(v)
	if err != nil {
		http.Error(w, "failed to write JSON Response", http.StatusInternalServerError)
	}
}

type Server struct {
	listenAddr string
	store      Storage
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
	router.HandleFunc("/test", s.handleTest).Methods(http.MethodGet)

	log.Println("JSON API server is running on port:", s.listenAddr)
	http.ListenAndServe(s.listenAddr, router)

}

func (s *Server) handleTest(w http.ResponseWriter, r *http.Request) {
	WriteJSON(w, http.StatusOK, "Server is running")
}

func (s *Server) handleregister(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var newuser NewUserRequest
		err := json.NewDecoder(r.Body).Decode(&newuser)
		if err != nil {
			WriteJSON(w, http.StatusBadRequest, fmt.Errorf("not of correct formate"))
			return
		}
		user, err := s.store.NewRegistraion(newuser)
		if err != nil {
			WriteJSON(w, http.StatusInternalServerError, fmt.Errorf("error occured"))
			return
		}
		token, err := GenerateToken()
		if err != nil {
			WriteJSON(w, http.StatusInternalServerError, fmt.Errorf("could not generate token"))
			return
		}
		err = s.store.EmailVerification(user.ID, token)
		if err != nil {
			WriteJSON(w, http.StatusInternalServerError, fmt.Errorf("not able to store token"))
			return
		}
		err = SendVerificationEmail(newuser.Email, token)
		if err != nil {
			WriteJSON(w, http.StatusInternalServerError, fmt.Errorf("error in sending mail"))
		}
		WriteJSON(w, http.StatusOK, "Email Sent Succesfully")
	} else {
		WriteJSON(w, http.StatusForbidden, fmt.Errorf("method not allowed"))
		
	}
}




func (s *Server) handleVerification(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		WriteJSON(w, http.StatusBadRequest, fmt.Errorf("token is required"))
		return
	}
	err := s.store.VerifyToken(token)
	if err != nil {
		WriteJSON(w, http.StatusForbidden, fmt.Errorf("invalid verification"))
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
	password := os.Getenv("emailpassword")
	smtpHost := os.Getenv("smtpHost")
	smtpPort := os.Getenv("smtpPort")

	link := os.Getenv("link") + "/verify?token=" + token

	msg := "From: " + from + "\n" +
		"To: " + email + "\n" +
		"Subject: Email Verification\n\n" +
		"Click the link to verify your email: " + link

	auth := smtp.PlainAuth("", from, password, smtpHost)
	return smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{email}, []byte(msg))

}
