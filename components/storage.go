package components

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type Storage interface {
	NewRegistraion(NewUserRequest) (*User, error)
	EmailVerification(uint64, string) error
	VerifyToken(string) error
}

type PostgresStore struct {
	db *sql.DB
}

func (s *PostgresStore) Init() error {
	err := s.CreateUsersTable()
	if err != nil {
		return err
	}
	err = s.CreateEmalVerificationTable()
	if err != nil {
		return err
	}
	return nil
}

func NewPostgresStore() (*PostgresStore, error) {
	connstr := os.Getenv("ConnectionString")
	db, err := sql.Open("postgres", connstr)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return &PostgresStore{
		db: db,
	}, nil
}

func (s *PostgresStore) CreateUsersTable() error {
	query := `create table if not exists users(
	id integer generated always as identity primary key,
	email varchar(255) not null,
	encrypted_password varchar(100) not null,
	verified boolean default false,
	)`
	_, err := s.db.Exec(query)
	return err
}

func (s *PostgresStore) insertIntoUser(newuser NewUserRequest) (*User, error) {
	query := `insert into users
	(email,encrypted_password,verified)
	values($1,$2,$3)
	`
	encpw, err := bcrypt.GenerateFromPassword([]byte(newuser.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	row := s.db.QueryRow(query, newuser.Email, string(encpw), 0)
	var user User
	err = row.Scan(&user.ID, &user.Email, &user.Encrypted_Password, &user.Verified)
	if err != nil {
		return nil, err
	}
	return &user, nil

}

func (s *PostgresStore) CreateEmalVerificationTable() error {
	query := `create table if not exists emailverification(
	user_id integer,
	token varchar(32) not null,
	expires_at timestamp not null,
	foreign key (user_id) references users(id),
	)`
	_, err := s.db.Exec(query)
	return err
}

func (s *PostgresStore) insertIntoEmailVerification(userID uint64, token string) error {
	expiration := time.Now().Add(5 * time.Minute)
	query := `insert into emailverification(user_id,token,expires_at)
	values($1,$2,$3)
	`
	_, err := s.db.Exec(
		query,
		userID,
		token,
		expiration,
	)
	if err != nil {
		return err
	}
	return nil
}

func (s *PostgresStore) NewRegistraion(newuser NewUserRequest) (*User, error) {
	user, err := s.insertIntoUser(newuser)
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (s *PostgresStore) EmailVerification(userID uint64, token string) error {
	err := s.insertIntoEmailVerification(userID, token)
	if err != nil {
		return err
	}
	return nil

}
func (s *PostgresStore) VerifyToken(token string) error {
	var userID uint64
	var expiresAt time.Time

	rows := s.db.QueryRow("select  expires_at from emailverification where token=$1", token)
	err := rows.Scan(&userID, &expiresAt)
	if err != nil {
		return fmt.Errorf("Verify Again")
	}
	if time.Now().After(expiresAt) {
		return fmt.Errorf("token expired")
	}
	_, err = s.db.Exec("update users set verified=1 where id=$1", userID)
	if err != nil {
		return err
	}
	_, err = s.db.Exec("Delete from emailverification where token=$1", token)
	return err
}
