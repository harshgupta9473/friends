package components

import (
	"crypto/rand"
	"encoding/hex"
	"net/smtp"
	"os"
)

func GenerateToken() (string, error) {
	token := make([]byte, 16)
	_, err := rand.Read(token)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(token), nil
}

func SendVerificationEmail(email, token string) error {
	from := os.Getenv("emailID")
	password := os.Getenv("emailpassword")
	smtpHost := os.Getenv("smtpHost")
	smtpPort := os.Getenv("smtpPort")

	link := os.Getenv("link") + "/verify?token" + token

	msg := "From: " + from + "\n" +
		"To: " + email + "\n" +
		"Subject: Email Verification\n\n" +
		"Click the link to verify your email: " + link

	auth := smtp.PlainAuth("", from, password, smtpHost)
	return smtp.SendMail(smtpHost+":"+smtpPort, auth, from, []string{email}, []byte(msg))

}
