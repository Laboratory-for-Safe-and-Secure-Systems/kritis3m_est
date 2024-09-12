package db

import (
	"io"
	"log"
	"net/http"
	"time"
)

func (db *DB) SaveHTTPRequest(r *http.Request) error {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		log.Println("Failed to read request body:", err)
		return err
	}
	body := string(bodyBytes)

	r.Body.Close()

	headers := ""
	for name, values := range r.Header {
		for _, value := range values {
			headers += name + ": " + value + "\n"
		}
	}

	requestRecord := HTTPRequest{
		Method:    r.Method,
		URL:       r.URL.String(),
		Headers:   headers,
		Body:      body,
		RemoteIP:  r.RemoteAddr,
		CreatedAt: time.Now(),
	}

	err = db.Create(&requestRecord)
	if err != nil {
		log.Println("Failed to save request to database:", err)
		return err
	}

	log.Printf("Saved request: %+v\n", requestRecord)
	return nil
}
