package main

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq"
)

type Book struct{
	isbn string
	title string
	author string
	price float32
}
func main(){
	db,err:=sql.Open("postgres","postgres://jashfeer:123@localhost/bookstore?sslmode=disable")
	if err!=nil{
		panic(err)
	}
	defer db.Close()
	if err=db.Ping();err!=nil{
		panic(err)
	}
	fmt.Println("you are connected to databace")
	rows,err:=db.Query("SELECT*FROM books")
	if err!=nil{
		panic(err)
	}
	defer rows.Close()

	bks:=make([]Book,0)
	for rows.Next(){
		bk:=Book{}
		err:=rows.Scan(&bk.isbn,&bk.title,&bk.author,&bk.price) //order matters
		if err!=nil{
			panic(err)
		}
		bks=append(bks,bk)
	}
	if err=rows.Err();err!=nil{
		panic(err)
	}
	for _,bk:=range bks{
		//print(bk.isbn, bk.title,bk.author, bk.price)
		fmt.Printf("%s,%s,%s,%f \n",bk.isbn,bk.title,bk.author,bk.price)

	}















}