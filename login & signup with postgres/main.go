package main

import (
	//"database/sql"
	"fmt"
	"net/http"
	"os"
	"text/template"

	_ "github.com/lib/pq"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/driver/postgres"
)

var db *gorm.DB
var tpl *template.Template
var store= sessions.NewCookieStore([]byte("super-secret"))


func openDB()(*gorm.DB,error){
	godotenv.Load()
	dbhost:=os.Getenv("dbHost")
	dbuser:=os.Getenv("dbUser")
	dbpassword:=os.Getenv("dbPassword")
	dbname:=os.Getenv("dbName")
	dbport:=os.Getenv("dbPort")
	dsn:=fmt.Sprintf("host=%s user=%s password=%s dbname=%s sslmode=disable port=%s",dbhost,dbuser,dbpassword,dbname,dbport)
	Db,err:=gorm.Open(postgres.Open(dsn))
	if err!=nil{
		return nil,err
	}
	return Db,nil
}


func init() {
	var err error
	db,err=openDB()
	//db, err = sql.Open("postgres", "postgres://jashfeer:123@localhost/mydb?sslmode=disable")
	if err != nil {
		panic(err)
	}
	// if err = db.Ping(); err != nil {
	// 	panic(err)
	// }
	fmt.Println("you connected to your database.")
	tpl = template.Must(template.ParseGlob("templates/*.html"))
}
type user struct {
	Id        string
	Firstname string
	Lastname  string
	Email     string
	Password  string
	Key       string
}

func main() {
	http.HandleFunc("/", index)
	http.HandleFunc("/login", loginFrom)
	http.HandleFunc("/login/process", loginProcess)
	http.HandleFunc("/signup", signupFrom)
	http.HandleFunc("/signup/process", signupProcess)
	http.HandleFunc("/delete", deleteProcess)
	http.HandleFunc("/welcome", welcomePage)
	http.HandleFunc("/admin/panal", adminPanal)
	http.HandleFunc("/update", updateForm)
	http.HandleFunc("/update/process", updateProcess)
	http.HandleFunc("/user/panal", userPanal)
	http.HandleFunc("/logout", logout)
	http.ListenAndServe(":3030", nil)
}



func alreadyLoggedIn(res http.ResponseWriter, req *http.Request)bool{
	fmt.Println("alreadyLoggedIn")
	session,_:=store.Get(req,"session")
	_,ok:=session.Values["id"]
	return ok
}
func getUser (res http.ResponseWriter,req *http.Request)user{
	fmt.Println("getUser")
	session,_:=store.Get(req,"session")
	id,ok:=session.Values["id"]
	fmt.Println("id from session : ",id)
	var u user
	if ok {
	//db.QueryRow("SELECT id,firstname,lastname,email,password,key FROM users WHERE id=$1", id).Scan(&u.Id, &u.Firstname, &u.Lastname, &u.Email, &u.Password, &u.Key)
	db.Where("id = ?", id).First(&u)

	
	fmt.Println("db user : ",u)
	return u
	}
	fmt.Println("db user : err",u)
	return u
}




func index(res http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(res,req) {
		http.Redirect(res, req, "/welcome", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(res, "index.html", 301)
}

func welcomePage(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(res,req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	u := getUser(res,req)
	if u.Key == "admin" {
		tpl.ExecuteTemplate(res, "adminWelcome.html", u)
	} else {
		tpl.ExecuteTemplate(res, "userWelcome.html", u)
	}
}

func loginFrom(res http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(res,req) {
		http.Redirect(res, req, "/welcome", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(res, "login.html", nil)
}


func loginProcess(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		tpl.ExecuteTemplate(res, "login.html", nil)
		return
	}
	ur := user{}
	email := req.FormValue("email")
	password := req.FormValue("password")
	//err := db.QueryRow("SELECT id,firstname,lastname,email,password,key FROM users WHERE email=$1", email).Scan(&ur.Id, &ur.Firstname, &ur.Lastname, &ur.Email, &ur.Password, &ur.Key)
	result :=db.Where("email = ?", email).First(&ur)
	if result.Error != nil {
		tpl.ExecuteTemplate(res, "login.html", "check username and password")
		return
	}
	result.Error = bcrypt.CompareHashAndPassword([]byte(ur.Password), []byte(password))
	if result.Error == nil {
		session,_:=store.Get(req,"session")
		session.Values["id"]=ur.Id
		session.Save(req,res)
		http.Redirect(res, req, "/welcome", http.StatusSeeOther)
		return
	}
		fmt.Println("incorrect password")
		tpl.ExecuteTemplate(res, "login.html", "check username and password")
}

func signupFrom(res http.ResponseWriter, req *http.Request) {
	if alreadyLoggedIn(res,req) {
		http.Redirect(res, req, "/welcome", http.StatusSeeOther)
		return
	}
	tpl.ExecuteTemplate(res, "signup.html", nil)
}


func signupProcess(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		tpl.ExecuteTemplate(res, "signup.html", 300)
		return
	}
	ur := user{}
	ur.Firstname = req.FormValue("firstname")
	ur.Lastname = req.FormValue("lastname")
	ur.Email = req.FormValue("email")
	password := req.FormValue("password")
	ur.Key = req.FormValue("key")

	//var User string

	err:=db.Where("email = ?", ur.Email).First(&ur).Error

	switch {
	case err == gorm.ErrRecordNotFound:
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(res, "Server error, unable to create your account.", 500)
			return
		}
		ur.Password = string(hashedPassword)
		db.Select("firstname", "lastname", "email","password","key").Create(&ur)
		if err != nil {
			http.Error(res, "Server error, unable to create your account.", 500)
			return
		}
		db.Where("email = ?", ur.Email).First(&ur)

		//create session

		session,_:=store.Get(req,"session")
		session.Values["id"]= ur.Id
		session.Save(req,res)
		http.Redirect(res, req, "/welcome", http.StatusSeeOther)
		return
	case err != nil:
		http.Error(res, "Server error, unable to create your account.", 500)
		return
	default:
		fmt.Println("sorrry")
		http.Redirect(res, req, "/", 301)

	}
}





func userPanal(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(res,req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	u := getUser(res,req)
	if u.Key=="admin"{
		http.Redirect(res, req, "/", http.StatusSeeOther)
	}
	if req.Method != "GET" {
		http.Error(res, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	tpl.ExecuteTemplate(res, "userPanal.html", u)
}


func adminPanal(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(res,req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	u:=getUser(res,req)
	if u.Key=="user"{
		http.Redirect(res, req, "/", http.StatusSeeOther)
	}
	if req.Method != "GET" {
		http.Error(res, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
/////////////////////
	urs := make([]user, 0)
	result:=db.Find(&urs)
	if result.Error != nil {
		http.Error(res, http.StatusText(500), 500)
		return
	}
/////////////////////////
	tpl.ExecuteTemplate(res, "adminPanal.html", urs)

}


func deleteProcess(res http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		http.Error(res, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	id := req.FormValue("id")
	if id == "" {
		http.Error(res, http.StatusText(400), http.StatusBadRequest)
		return
	}
	fmt.Println(id)
	//_, err := db.Exec("DELETE FROM users WHERE id=$1;", id)
	ur:=user{}
	result:=db.Where("id = ?", id).Delete(&ur)
	if result.Error != nil {
		http.Error(res, http.StatusText(500), http.StatusInternalServerError)
		return
	}
	http.Redirect(res, req, "/admin/panal", http.StatusSeeOther)
}


func updateForm(res http.ResponseWriter, req *http.Request) {
	if req.Method != "GET" {
		http.Error(res, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	id := req.FormValue("id")
	if id == "" {
		http.Error(res, http.StatusText(400), http.StatusBadRequest)
		return
	}
	ur := user{}
	//row := db.QueryRow("SELECT* FROM users WHERE id=$1", id)
	//err := row.Scan(&ur.Id, &ur.Firstname, &ur.Lastname, &ur.Email, &ur.Password, &ur.Key)
	result:=db.Where("id = ?", id).First(&ur)
	switch {
	case result.Error == gorm.ErrRecordNotFound:
		http.NotFound(res, req)
		return
	case result.Error != nil:
		fmt.Println(id)

		http.Error(res, http.StatusText(500), http.StatusInternalServerError)
		return
	}
	tpl.ExecuteTemplate(res, "update.html", ur)
}

func updateProcess(res http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(res, http.StatusText(405), http.StatusMethodNotAllowed)
		return
	}
	u:=getUser(res,req)
	id := req.FormValue("id")

	ur := user{}
	ur.Firstname = req.FormValue("firstname")
	ur.Lastname = req.FormValue("lastname")
	ur.Email = req.FormValue("email")
	ur.Key = req.FormValue("key")

	//_, err := db.Exec("UPDATE users SET firstname=$2,lastname=$3,email=$4,key=$5 WHERE id=$1", ur.Id, ur.Firstname, ur.Lastname, ur.Email, ur.Key)
	result:=db.Model(ur).Where("id=?",id).Updates(ur)
	if result.Error != nil {
		http.Error(res, http.StatusText(500), http.StatusInternalServerError)
		return
	}
	if u.Key == "admin" {
		http.Redirect(res, req, "/admin/panal", http.StatusSeeOther)
	} else {
		http.Redirect(res, req, "/user/panal", http.StatusSeeOther)
	}

}

func logout(res http.ResponseWriter, req *http.Request) {
	if !alreadyLoggedIn(res,req) {
		http.Redirect(res, req, "/", http.StatusSeeOther)
		return
	}
	session,_:=store.Get(req,"session")
	delete(session.Values,"id")
	session.Save(req,res)
	http.Redirect(res, req, "/", http.StatusSeeOther)
}