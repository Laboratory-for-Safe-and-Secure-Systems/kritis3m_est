package main

import (
	_ "embed"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"text/template"
	"time"

	"github.com/Laboratory-for-Safe-and-Secure-Systems/est/internal/alogger"
	"github.com/Laboratory-for-Safe-and-Secure-Systems/est/internal/db"
	"github.com/gorilla/websocket"
	_ "github.com/mattn/go-sqlite3"
)

var logger = alogger.New(os.Stderr)

// WebSocket upgrader to upgrade HTTP connections to WebSocket connections
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// List of active WebSocket connections
var clients = make(map[*websocket.Conn]bool)
var broadcast = make(chan string)

//go:embed index.htmx
var embeddedIndex []byte

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		logger.Errorf("Failed to upgrade connection: %v", err)
	}
	defer ws.Close()

	clients[ws] = true

	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			logger.Errorf("Failed to read message: %v", err)
			delete(clients, ws)
			break
		}
		logger.Infof("Received message: %s", string(msg))
	}
}

// generateDynamicTemplate generates the table headers and rows dynamically using reflection
func generateDynamicTemplate(data []db.Certificate) (string, error) {
	if len(data) == 0 {
		return "<tr><td colspan=\"3\">No data available</td></tr>", nil
	}

	// Exclude the field "Status" from the table
	excludeField := "Model"

	// Use reflection to get the type of the first element
	elemType := reflect.TypeOf(data[0])

	// Generate table headers based on struct fields
	var headers []string
	for i := 0; i < elemType.NumField(); i++ {
		field := elemType.Field(i)
		if field.Name != excludeField {
			headers = append(headers, fmt.Sprintf("<th class=\"px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider\">%s</th>", field.Name))
		}
	}

	// Generate table rows
	var rows []string
	for _, cert := range data {
		var row []string
		val := reflect.ValueOf(cert)
		for i := 0; i < val.NumField(); i++ {
			field := elemType.Field(i)
			fieldValue := val.Field(i)

			// If the field is not excluded, add it as a table cell
			if field.Name != excludeField {
				// Check if the field name contains "At" and is of type time.Time
				if strings.Contains(field.Name, "At") && fieldValue.Type() == reflect.TypeOf(time.Time{}) {
					t := fieldValue.Interface().(time.Time)
					// Format the time and add it to the row
					// paddinf 12px all around
					row = append(row, fmt.Sprintf("<td class=\"text-center p-3 text-gray-500\">%s</td>", t.Format("2006-01-02 15:04:05")))
				} else {
					// For non-time fields, just add the value
					row = append(row, fmt.Sprintf("<td class=\"text-center p-3 text-gray-500\">%v</td>", fieldValue.Interface()))
				}
			}
		}
		rows = append(rows, fmt.Sprintf("<tr class=\"border-b\">%s</tr>", strings.Join(row, "")))
	}

	// Combine headers and rows into a complete table body
	html := fmt.Sprintf("<thead class=\"bg-gray-200\"><tr>%s</tr></thead><tbody>%s</tbody>", strings.Join(headers, ""), strings.Join(rows, ""))
	return html, nil
}

// handleData handles the HTMX request and returns the formatted data
func handleData(w http.ResponseWriter, _ *http.Request, newDB *db.DB) {
	certs := newDB.GetCertificates()

	tmpl, err := generateDynamicTemplate(certs)

	t, err := template.New("tableRows").Parse(tmpl)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		logger.Errorf("Failed to parse template: %v", err)
		return
	}

	// Write the HTML response
	w.Header().Set("Content-Type", "text/html")
	if err := t.Execute(w, certs); err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		logger.Errorf("Failed to execute template: %v", err)
	}
}

// Broadcast changes to all clients
func broadcastMessages() {
	for {
		msg := <-broadcast
		for client := range clients {
			err := client.WriteMessage(websocket.TextMessage, []byte(msg))
			if err != nil {
				logger.Errorf("Failed to write message: %v", err)
				client.Close()
				delete(clients, client)
			}
		}
	}
}

// Watch for changes in SQLite (or any other method to detect changes)
func watchForDatabaseChanges() {
	// Simulating database changes randomly at intervals
	for {
		time.Sleep(1 * time.Second)
		broadcast <- "Database changed!"
	}
}

func main() {
	newDB, err := db.NewDB("sqlite", "test.db")
	if err != nil {
		logger.Errorf("Failed to connect to database: %v", err)
	}
	defer newDB.Close()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		embeddedIndex = []byte(strings.ReplaceAll(string(embeddedIndex), "localhost:8080", r.Host))
		w.Write(embeddedIndex)
	})

	// Serve WebSocket connections
	http.HandleFunc("/ws", handleConnections)

	// Serve data changes
	http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		handleData(w, r, newDB)
	})

	http.HandleFunc("/chart-data", func(w http.ResponseWriter, r *http.Request) {
		// mock data json with two properties "certificates" and "subjects"
		certs := newDB.GetCertificates()
		subjects := newDB.GetSubjects()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"certificates": ` + fmt.Sprintf("%d", len(certs)) + `, "subjects": ` + fmt.Sprintf("%d", len(subjects)) + `}`))
	})

	// Start broadcasting messages
	go broadcastMessages()

	// Simulate watching for database changes
	go watchForDatabaseChanges()

	// Start the server
	logger.Infof("Starting server on :8080")
	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		logger.Errorf("Failed to start server: %v", err)
	}
}
