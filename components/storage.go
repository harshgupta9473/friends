package components

import (
	"fmt"
	"log"
	"os"
	"time"

	"database/sql"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

type Storage interface {
	NewRegistraion(NewUserRequest) (*User, error)
	StoreInEmailVerification(uint64, string) error
	VerifyToken(string) error
	GetUserByEmail(string) (*User, error)
	StoreIntoResetPassword(uint64, string) error
	VerifyTokenforResetPassword(string,uint64)error
	ResetPassword(uint64,string)error
	DeleteTokenforForgetPasswordfromDB(string,uint64)error
	AuthenticateLogin(string ,string) (*User,bool)
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
	err = s.CreateResetPasswordTable()
	if err != nil {
		return err
	}
	return nil
}

func NewPostgresStore() (*PostgresStore, error) {
	err := godotenv.Load()
	if err != nil {
		return nil, err
	}
	connstr := os.Getenv("connstr")
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
	verified boolean default false
	)`
	_, err := s.db.Exec(query)
	return err
}

func (s *PostgresStore) insertIntoUser(newuser NewUserRequest) (*User, error) {
	query := `insert into users
	(email,encrypted_password,verified)
	values($1,$2,$3)`
	encpw, err := bcrypt.GenerateFromPassword([]byte(newuser.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	_, err = s.db.Exec(query, newuser.Email, string(encpw), false)
	if err != nil {
		return nil, err
	}
	user, err := s.GetUserByEmail(newuser.Email)
	return user, err

}

func (s *PostgresStore) GetUserByEmail(email string) (*User, error) {
	query := `SELECT id, email, encrypted_password, verified FROM users WHERE email = $1`
	rows, err := s.db.Query(query, email)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	user := new(User)
	if rows.Next() {
		err := rows.Scan(&user.ID, &user.Email, &user.Encrypted_Password, &user.Verified)
		if err != nil {
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("user not found")
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}

	return user, nil
}


func (s *PostgresStore) CreateEmalVerificationTable() error {
	query := `create table if not exists emailverification(
	user_id integer,
	token varchar(32) not null,
	expires_at timestamp not null,
	foreign key (user_id) references users(id)
	)`
	_, err := s.db.Exec(query)
	return err
}

func (s *PostgresStore)CreateResetPasswordTable()error{
	query:=`create table if not exists resetpassword(
	user_id integer,
	token varchar(32) not null,
	expires_at timestamp not null,
	foreign key (user_id) references users(id)
	)`
	_, err := s.db.Exec(query)
	return err
}

func(s *PostgresStore)insertIntoResetPassword(userID uint64,token string)error{
	expiration:=time.Now().Add(5*time.Minute)
	query:=`insert into resetpassword(user_id,token,expires_at)
	values($1,$2,$3)`
	_,err:=s.db.Exec(query,userID,token,expiration)
	if err!=nil{
		log.Println(err)
		return err
	}
	return nil
}

func (s *PostgresStore) StoreIntoResetPassword(userID uint64, token string) error {
	err := s.insertIntoResetPassword(userID, token)
	if err != nil {
		return err
	}
	return nil
}



func (s *PostgresStore) insertIntoEmailVerification(userID uint64, token string) error {
	expiration := time.Now().Add(5 * time.Minute)
	query := `insert into emailverification(user_id,token,expires_at)
	values($1,$2,$3)`
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

func (s *PostgresStore) StoreInEmailVerification(userID uint64, token string) error {
	err := s.insertIntoEmailVerification(userID, token)
	if err != nil {
		return err
	}
	return nil

}
func (s *PostgresStore) VerifyToken(token string) error {
	var userID uint64
	var expiresAt time.Time

	rows := s.db.QueryRow("select user_id, expires_at from emailverification where token=$1", token)
	err := rows.Scan(&userID, &expiresAt)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("verify again")
	}
	if time.Now().After(expiresAt) {
		_,err= s.db.Exec("delete from emailverification where token=$1", token)
		log.Println(err)
		return fmt.Errorf("token expired")
	}
	_, err = s.db.Exec("update users set verified=true where id=$1", userID)
	if err != nil {
		log.Println(err)
		return err
	}
	_, err = s.db.Exec("delete from emailverification where user_id=$1 token=$2",userID, token)
	log.Println(err)
	return err
}

func (s *PostgresStore)VerifyTokenforResetPassword(token string,id uint64)error{
	var expiresAt time.Time

	query:=`select expires_at from resetpassword where user_id=$1 and token=$2`
	rows:=s.db.QueryRow(query,id,token)
	err:=rows.Scan(&expiresAt)
	if err!=nil{
		log.Println(err)
		return err
	}
	
	if time.Now().After(expiresAt){
		log.Println("token expired")
		log.Println('\n',err)
		return fmt.Errorf("token expired")
	}
	return nil
}

func(s *PostgresStore)DeleteTokenforForgetPasswordfromDB(token string,id uint64)error{
	_,err:=s.db.Exec("delete from resetpassword where user_id=$1 and token=$2",id,token)
	if err!=nil{
		return err
	}
	return nil
}

func(s *PostgresStore)ResetPassword(userID uint64,newPassword string)error{
	encpw,err:=bcrypt.GenerateFromPassword([]byte(newPassword),bcrypt.DefaultCost)
	if err!=nil{
		return fmt.Errorf("internal server error")
	}
	query:=`update users set encrypted_password=$1 where id=$2`
	_,err=s.db.Exec(query,encpw,userID)
	if err!=nil{
		log.Println(err)
		return err
	}
	return nil
}

func verifyPassword(encpw string,password string)bool{
	return bcrypt.CompareHashAndPassword([]byte(encpw),[]byte(password))==nil
}


func(s *PostgresStore)AuthenticateLogin(email ,password string) (*User,bool){
  user,err:=s.GetUserByEmail(email)
  if err!=nil{
	return nil,false
  }
  
  if !verifyPassword(user.Encrypted_Password,password){
	return nil,false
  }
  return user,true

}