package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
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

type CONFIG_TYPE int

const (
	CLASSIC CONFIG_TYPE = 1
	HYBRID  CONFIG_TYPE = 2
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

func generateDynamicTemplate(data interface{}, excludeFields []string) (string, error) {
	// Validate that the input is a slice
	val := reflect.ValueOf(data)
	if val.Kind() != reflect.Slice {
		return "", fmt.Errorf("data must be a slice")
	}

	// Check if the slice is empty
	if val.Len() == 0 {
		return "<tr><td colspan=\"3\">No data available</td></tr>", nil
	}

	// Use reflection to get the element type of the slice
	elemType := val.Type().Elem()
	if elemType.Kind() != reflect.Struct {
		return "", fmt.Errorf("data must be a slice of structs")
	}

	// Generate table headers based on struct fields
	var headers []string
	for i := 0; i < elemType.NumField(); i++ {
		field := elemType.Field(i)
		// Skip excluded fields
		if contains(excludeFields, field.Name) {
			continue
		}
		headers = append(headers, fmt.Sprintf("<th class=\"px-6 py-3 text-center text-xs font-medium text-gray-500 uppercase tracking-wider\">%s</th>", field.Name))
	}

	// Generate table rows
	var rows []string
	for i := 0; i < val.Len(); i++ {
		var row []string
		item := val.Index(i)
		for j := 0; j < item.NumField(); j++ {
			field := elemType.Field(j)
			fieldValue := item.Field(j)

			// Skip excluded fields
			if contains(excludeFields, field.Name) {
				continue
			}

			// Check if the field name contains "At" and is of type time.Time
			if strings.Contains(field.Name, "At") && fieldValue.Type() == reflect.TypeOf(time.Time{}) {
				t := fieldValue.Interface().(time.Time)
				// if no time is set, display "Not Seen"
				if t.IsZero() {
					row = append(row, fmt.Sprintf("<td class=\"text-center p-3 text-gray-500\"></td>"))
				} else {
					row = append(row, fmt.Sprintf("<td class=\"text-center p-3 text-gray-500\">%s</td>", t.Format("2006-01-02 15:04:05")))
				}
				// if fieldValue is a contains "Status" and is of type string then do a traffic light style
			} else if strings.Contains(field.Name, "Status") {
				switch fieldValue.Interface() {
				case db.ErrorState, db.CertificateStatusRevoked:
					row = append(row, `
        <td class="text-center p-3">
          <div class="relative inline-block w-6 h-6">
            <div class="absolute inset-0 rounded-full bg-red-400 opacity-75 animate-ping"></div>
            <div class="absolute inset-1 rounded-full bg-red-500"></div>
          </div>
        </td>
          `)

				case db.NotSeen:
					row = append(row, `
        <td class="text-center p-3">
          <div class="relative inline-block w-6 h-6">
            <div class="absolute inset-0 rounded-full bg-gray-400 opacity-75"></div>
            <div class="absolute inset-1 rounded-full bg-gray-500"></div>
          </div>
        </td>
          `)

				case db.NodeRequestedConfig, db.CertificateStatusPending:
					row = append(row, `
        <td class="text-center p-3">
          <div class="relative inline-block w-6 h-6">
            <div class="absolute inset-0 rounded-full bg-yellow-400 opacity-75 animate-ping"></div>
            <div class="absolute inset-1 rounded-full bg-yellow-500"></div>
          </div>
        </td>
          `)

				case db.Running, db.CertificateStatusActive:
					row = append(row, `
        <td class="text-center p-3">
          <div class="relative inline-block w-6 h-6">
            <div class="absolute inset-0 rounded-full bg-green-400 opacity-75 animate-ping"></div>
            <div class="absolute inset-1 rounded-full bg-green-500"></div>
          </div>
        </td>
          `)

				default:
					row = append(row, `
        <td class="text-center p-3">
          <div class="relative inline-block w-6 h-6">
            <div class="absolute inset-0 rounded-full bg-gray-400 opacity-75"></div>
            <div class="absolute inset-1 rounded-full bg-gray-500"></div>
          </div>
        </td>
          `)
				}
			} else {
				row = append(row, fmt.Sprintf("<td class=\"text-center p-3 text-gray-500\">%v</td>", fieldValue.Interface()))
			}
		}
		rows = append(rows, fmt.Sprintf("<tr class=\"border-b\">%s</tr>", strings.Join(row, "")))
	}

	// Reverse sort the rows
	for i, j := 0, len(rows)-1; i < j; i, j = i+1, j-1 {
		rows[i], rows[j] = rows[j], rows[i]
	}

	// Combine headers and rows into a complete table body
	html := fmt.Sprintf("<thead class=\"bg-gray-200\"><tr>%s</tr></thead><tbody>%s</tbody>", strings.Join(headers, ""), strings.Join(rows, ""))
	return html, nil
}

// contains checks if a slice contains a specific string
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// handleNodeData handles the HTMX request and returns the formatted data
func handleNodeData(w http.ResponseWriter, _ *http.Request, newDB *db.DB) {
	nodes, err := newDB.GetNodes()

	tmpl, err := generateDynamicTemplate(nodes, []string{"Model", "ID"})

	t, err := template.New("tableRows").Parse(tmpl)
	if err != nil {
		http.Error(w, "Error rendering template", http.StatusInternalServerError)
		logger.Errorf("Failed to parse template: %v", err)
		return
	}

	// Write the HTML response
	w.Header().Set("Content-Type", "text/html")
	if err := t.Execute(w, nodes); err != nil {
		http.Error(w, "Error executing template", http.StatusInternalServerError)
		logger.Errorf("Failed to execute template: %v", err)
	}
}

// handleData handles the HTMX request and returns the formatted data
func handleData(w http.ResponseWriter, _ *http.Request, newDB *db.DB) {
	certs := newDB.GetCertificates()

	tmpl, err := generateDynamicTemplate(certs, []string{"Model"})

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
	certDBFile := flag.String("certDB", "", "Path to the certificates database")
	nodesDBFile := flag.String("nodesDB", "", "Path to the nodes database")
	port := flag.String("port", "8080", "Port to run the server on")

	flag.Parse()
	if *certDBFile == "" || *nodesDBFile == "" {
		logger.Errorf("Database file path is required")
		os.Exit(1)
	}

	// Connect to the databases
	certDB, err := db.NewDB("sqlite", *certDBFile)
	nodesDB, err := db.NewDB("sqlite", *nodesDBFile)
	if err != nil {
		logger.Errorf("Failed to connect to database: %v", err)
	}
	defer certDB.Close()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		embeddedIndex = []byte(strings.ReplaceAll(string(embeddedIndex), "localhost:8080", r.Host))
		w.Write(embeddedIndex)
	})

	// Serve WebSocket connections
	http.HandleFunc("/ws", handleConnections)

	// Serve data changes
	http.HandleFunc("/data", func(w http.ResponseWriter, r *http.Request) {
		handleData(w, r, certDB)
	})

	http.HandleFunc("/nodes", func(w http.ResponseWriter, r *http.Request) {
		handleNodeData(w, r, nodesDB)
	})

	http.HandleFunc("/chart-data", func(w http.ResponseWriter, r *http.Request) {
		// mock data json with two properties "certificates" and "subjects"
		certs := certDB.GetCertificates()
		subjects := certDB.GetSubjects()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"certificates": ` + fmt.Sprintf("%d", len(certs)) + `, "subjects": ` + fmt.Sprintf("%d", len(subjects)) + `}`))
	})

	http.HandleFunc("/trigger", func(w http.ResponseWriter, r *http.Request) {
		// Read the request body
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			logger.Errorf("Failed to read request body: %v", err)
			http.Error(w, "Failed to read request body", http.StatusInternalServerError)
			return
		}
		r.Body.Close() // Close the original body to avoid leaks

		// Log the body payload
		logger.Infof("Body: %s", string(bodyBytes))

		// Body Payload
		type BPayload struct {
			CfgID int `json:"cfg_id"`
		}

		// Unmarshal the body payload
		var receivedBody BPayload
		err = json.Unmarshal(bodyBytes, &receivedBody)
		if err != nil {
			logger.Errorf("Failed to unmarshal JSON: %v", err)
			http.Error(w, "Failed to unmarshal JSON", http.StatusInternalServerError)
			return
		}

		logger.Infof("Received body CFG: %d", receivedBody.CfgID)

		// Payload represents the data to be sent to the backend
		type Payload struct {
			NodeID     int `json:"node_id"`
			ConfigType int `json:"cfg_id"`
		}

		logger.Infof("Received body: %v", receivedBody)

		var payloads []Payload
		if receivedBody.CfgID == int(CLASSIC) {
			payloads = []Payload{
				{
					NodeID:     1,
					ConfigType: 1,
				},
				{
					NodeID:     2,
					ConfigType: 3,
				},
				{
					NodeID:     3,
					ConfigType: 5,
				},
			}
		} else if receivedBody.CfgID == int(HYBRID) {
			payloads = []Payload{
				{
					NodeID:     1,
					ConfigType: 2,
				},
				{
					NodeID:     2,
					ConfigType: 4,
				},
				{
					NodeID:     3,
					ConfigType: 6,
				},
			}
		}

		// Encode the payloads into JSON
		payloadBytes, err := json.Marshal(payloads)
		if err != nil || len(payloads) == 0 {
			logger.Errorf("Failed to marshal JSON: %v", err)
			http.Error(w, "Failed to marshal JSON", http.StatusInternalServerError)
			return
		}

		logger.Infof("Payload: %s", payloadBytes)

		// Send POST to different backend
		response, err := http.Post("http://localhost:8181/api/trigger", "application/json", bytes.NewReader(payloadBytes))
		if err != nil {
			logger.Errorf("Failed to send POST request: %v", err)
			http.Error(w, "Failed to send POST request", http.StatusInternalServerError)
			return
		}
		defer func() {
			if closeErr := response.Body.Close(); closeErr != nil {
				logger.Errorf("Failed to close response body: %v", closeErr)
			}
		}()

		// Log response details
		responseBody, _ := io.ReadAll(response.Body) // Ignore errors here for simplicity
		logger.Infof("Response body: %s", string(responseBody))
		logger.Infof("Status code: %d", response.StatusCode)
		logger.Infof("Status: %s", response.Status)

		// Send 200 OK JSON response
		logger.Infof("Sending 200 OK")
		w.Header().Set("Content-Type", "application/json")
		if response.StatusCode != http.StatusOK {
			w.WriteHeader(http.StatusInternalServerError)
      w.Write(responseBody)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Write(responseBody)
		}
	})

    w.Write(responseBody)
	})

	// Start broadcasting messages
	go broadcastMessages()

	// Simulate watching for database changes
	go watchForDatabaseChanges()

	// Start the server
	logger.Infof("Starting server on :%s", *port)
	err = http.ListenAndServe(":"+*port, nil)
	if err != nil {
		logger.Errorf("Failed to start server: %v", err)
	}
}
