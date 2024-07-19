package components

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/mux"
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

	log.Println("JSON API server is running on port:", s.listenAddr)
	http.ListenAndServe(s.listenAddr,router)

}

func (s *Server) handleregister(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		var newuser NewUserRequest
		err := json.NewDecoder(r.Body).Decode(newuser)
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
			WriteJSON(w, http.StatusInternalServerError, err)
		}
		WriteJSON(w, http.StatusOK, "Registration successful! Please check your email to verify your account.")
		return
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
	return
}
