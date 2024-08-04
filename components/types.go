package components

import (
	"time"
)

type NewUserRequest struct {
	U_ID string `json:"userID"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	U_ID string `json:"userID"`
	Email string `json:"email"`
	Token string `json:"token"`
	Verified bool `json:"verified"`
}

type User struct {
	ID                 uint64 `json:"id"`
	U_ID               string `json:"userID"`
	Email              string `json:"email"`
	Encrypted_Password string `json:"-"`
	Verified           bool   `json:"verified"`
}

type UserProfile struct {
	U_ID     string `json:"userID"`
	Name     string  `json:"name"`
	Bio       string `json:"bio"`
	Interests string `json:"interests"`
}

type Friends struct{
	User_ID  string `json:"user"`
	F_ID string      `json:"friend"`
	Created_At time.Time `json:"createdAt"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email"`
}

type ResetPasswordRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type EmailVerification struct {
	User_ID   uint64    `json:"userid"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `jaon:"expiresat"`
}

func NewUser(email, password string) *NewUserRequest {

	return &NewUserRequest{
		Email:    email,
		Password: password,
	}
}
