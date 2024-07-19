package components

import "time"

type NewUserRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
}

type User struct {
	ID       uint64 `json:"id"`
	Email    string `json:"email"`
	Encrypted_Password string `json:"-"`
	Verified bool   `json:"verified"`
}



type EmailVerification struct {
	User_ID   uint64 `json:"userid"`
	Token     string `json:"token"`
	ExpiresAt time.Time `jaon:"expiresat"`
}

func NewUser(email,password string)*NewUserRequest{

	return &NewUserRequest{
		Email: email,
		Password: password,
	}
}
