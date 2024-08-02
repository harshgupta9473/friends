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
	"strconv"

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
	router.HandleFunc("/forgotpassword", s.ForgotPassword)
	router.HandleFunc("/test", s.handleTest)
	router.HandleFunc("/forgotpassword/verify", s.HandleForgotPassword)
	router.HandleFunc("/forgotpassword/verify/reset", s.HandleResetPassword)

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

func (s *Server) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var forgotReq ForgotPasswordRequest
	err := json.NewDecoder(r.Body).Decode(&forgotReq)
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError{Error: err.Error()})
		return
	}

	token, err := GenerateToken()
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError{Error: err.Error()})
		return
	}
	user, err := s.store.GetUserByEmail(forgotReq.Email)
	if err != nil {
		WriteJSON(w, http.StatusForbidden, serverError{Error: "user does not exist"})
		return
	}
	err = s.store.StoreIntoResetPassword(user.ID, token)
	if err != nil {
		WriteJSON(w, http.StatusForbidden, serverError{Error: err.Error()})
		return
	}
	stringID := strconv.Itoa(int(user.ID))
	err = SendPasswordVerificationEmail(forgotReq.Email, token, stringID)
	if err != nil {
		WriteJSON(w, http.StatusInternalServerError, serverError{Error: err.Error()})
		return
	}
	WriteJSON(w, http.StatusOK, "Password Verification link is sent to your Email, check your email")
}

func (s *Server) HandleForgotPassword(w http.ResponseWriter, r *http.Request) {
	err := s.VerifyResetPasswordToken(r)
	if err != nil {
		WriteJSON(w, http.StatusBadRequest, serverError{Error: err.Error()})
		return
	}
	WriteJSON(w, http.StatusOK, "authenticated")
}

func (s *Server) HandleResetPassword(w http.ResponseWriter, r *http.Request) {
	err := s.ResetPasswordFunc(r)
	if err != nil {
		WriteJSON(w, http.StatusGatewayTimeout, serverError{Error: "time out"})
		return
	}
	WriteJSON(w, http.StatusOK, "password reset successful go to login page to login")

}

func (s *Server) VerifyResetPasswordToken(r *http.Request) ( error) {
	token, userID, err := s.getTokenAndUSERID(r)
	if err != nil {
		return  err
	}
	err = s.store.VerifyTokenforResetPassword(token, userID)
	if err != nil {
		return  err
	}
	return  nil
}

func (s *Server) getTokenAndUSERID(r *http.Request) (string, uint64, error) {
	token := r.URL.Query().Get("token")
	stringID := r.URL.Query().Get("id")
	userID, err := strconv.Atoi(stringID)
	if err != nil {
		return "", 0, err
	}
	return token, uint64(userID), nil
}

func (s *Server) ResetPasswordFunc(r *http.Request) error {

	 err := s.VerifyResetPasswordToken(r)
	 if err!=nil{
		return err
	 }
	 token, userID, err := s.getTokenAndUSERID(r)
	 if err!=nil{
		return err
	 }

	err = s.store.DeleteTokenforForgetPasswordfromDB(token,userID)
	if err != nil {
		return fmt.Errorf("not authorised")
	}
	var newpasswordreq ResetPasswordRequest
	err = json.NewDecoder(r.Body).Decode(&newpasswordreq)
	if err != nil {
		return err
	}
	err = s.store.ResetPassword(uint64(userID), newpasswordreq.Password)
	if err != nil {
		return err
	}
	err=sendPasswordResetSuccessfulEmai(newpasswordreq.Email)
	if err!=nil{
		return err
	}
	return nil
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
	password := os.Getenv("apppassword")
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

func ValidPassword(newuser *NewUserRequest, user *User) bool {
	return bcrypt.CompareHashAndPassword([]byte(user.Encrypted_Password), []byte(newuser.Password)) == nil
}

func SendPasswordVerificationEmail(email, token string, id string) error {
	err := godotenv.Load()
	if err != nil {
		return err
	}
	from := os.Getenv("emailID")
	company := os.Getenv("companyName")
	password := os.Getenv("apppassword")
	smtpHost := os.Getenv("smtpHost")
	smtpPort := os.Getenv("smtpPort")

	link := os.Getenv("link") + "/forgotpassword/verify?token=" + token + "&id=" + id

	msg := "Greetings from " + company + ",\n\n\n" +
		"We received a password recovery request associated with this e-mail address. Please click the below URL to reset your password at " + company + "\n\n" +
		link + "\n\n" +
		"If you did not initiate this password recovery request you can safely ignore this e-mail. Rest assured all your information aresafe.\n\n" +
		company +
		" will never e-mail you and ask you to disclose or verify your " + company + " password. If you receive a suspicious e-mail with a link to update your account information, do not click on the link!" + "\n\nPlease do not reply to this e-mail. This mailbox is not monitored and you will not receive a response."

	auth := smtp.PlainAuth("", from, password, smtpHost)
	return smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{email}, []byte(msg))
}

func sendPasswordResetSuccessfulEmai(email string)error{
	err:=godotenv.Load()
	if err!=nil{
		return err
	}
	from :=os.Getenv("emailID")
	password := os.Getenv("apppassword")
	company:=os.Getenv("companyName")
	smtpHost:=os.Getenv("smtpHost")
	smtpPort:=os.Getenv("smtpPort")

	msg:="Greetings from " + company + ",\n\n\n" +
	"Password reset success\n\n"+
	"Hello "+email+",\n\n"+
	"This is to confirm that you have successfully changed your password associated with"+company+"account. Please sign-in to your account."

	auth:=smtp.PlainAuth("",from,password,smtpHost)
	return smtp.SendMail(smtpHost+":"+smtpPort,auth,from,[]string{email},[]byte(msg))
}
