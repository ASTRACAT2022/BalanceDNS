package admin

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"dns-resolver/internal/metrics"
	"dns-resolver/plugins/adblock"
	"dns-resolver/plugins/hosts"
	"golang.org/x/crypto/bcrypt"
)

// Server provides an admin web interface.
type Server struct {
	addr         string
	metrics      *metrics.Metrics
	hosts        *hosts.HostsPlugin
	adblock      *adblock.AdBlockPlugin
	username     string
	passwordHash []byte
	sessionToken string
	sessionExpiry time.Time
}

// New creates a new admin server.
func New(addr string, m *metrics.Metrics, h *hosts.HostsPlugin, ab *adblock.AdBlockPlugin) *Server {
	// In a real application, load this from config
	username := "astracat"
	password := "astracat"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}

	return &Server{
		addr:         addr,
		metrics:      m,
		hosts:        h,
		adblock:      ab,
		username:     username,
		passwordHash: hash,
	}
}

// Start runs the admin server.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)

	// Protected routes
	mux.Handle("/", s.authMiddleware(http.HandlerFunc(s.handleStats)))
	mux.Handle("/change-password", s.authMiddleware(http.HandlerFunc(s.handleChangePassword)))
	mux.Handle("/api/hosts/reload", s.authMiddleware(http.HandlerFunc(s.handleHostsReload)))
	mux.Handle("/adblock/add", s.authMiddleware(http.HandlerFunc(s.handleAddBlocklist)))
	mux.Handle("/adblock/remove", s.authMiddleware(http.HandlerFunc(s.handleRemoveBlocklist)))
	mux.Handle("/adblock/reload", s.authMiddleware(http.HandlerFunc(s.handleAdBlockReload)))

	log.Printf("Starting admin server on %s", s.addr)
	if err := http.ListenAndServe(s.addr, mux); err != nil {
		log.Fatalf("Failed to start admin server: %v", err)
	}
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_token")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		if cookie.Value != s.sessionToken || time.Now().After(s.sessionExpiry) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	errorMessage := ""
	if r.Method == http.MethodPost {
		r.ParseForm()
		username := r.FormValue("username")
		password := r.FormValue("password")

		if username == s.username && bcrypt.CompareHashAndPassword(s.passwordHash, []byte(password)) == nil {
			token := make([]byte, 32)
			rand.Read(token)
			s.sessionToken = base64.StdEncoding.EncodeToString(token)
			s.sessionExpiry = time.Now().Add(12 * time.Hour)

			http.SetCookie(w, &http.Cookie{
				Name:    "session_token",
				Value:   s.sessionToken,
				Expires: s.sessionExpiry,
				Path:    "/",
			})
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
		errorMessage = "Invalid username or password"
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tpl, _ := template.New("login").Parse(loginPage)
	tpl.Execute(w, map[string]string{"Error": errorMessage})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.sessionToken = ""
	http.SetCookie(w, &http.Cookie{
		Name:    "session_token",
		Value:   "",
		Expires: time.Unix(0, 0),
		Path:    "/",
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	newPassword := r.FormValue("new_password")
	if len(newPassword) < 8 {
		// In a real app, you'd render this error nicely on the page
		http.Error(w, "Password must be at least 8 characters long", http.StatusBadRequest)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash new password", http.StatusInternalServerError)
		return
	}
	s.passwordHash = hash
	// Redirect with a success message
	http.Redirect(w, r, "/?message=Password+changed+successfully", http.StatusFound)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Query().Get("message")
	data := struct {
		Queries    int64
		Message    string
		Blocklists []string
	}{
		Queries:    s.metrics.GetQueries(),
		Message:    message,
		Blocklists: s.adblock.GetBlocklists(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tpl, _ := template.New("stats").Parse(statsPage)
	tpl.Execute(w, data)
}

func (s *Server) handleAddBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	url := r.FormValue("url")
	if url == "" {
		http.Error(w, "URL cannot be empty", http.StatusBadRequest)
		return
	}
	s.adblock.AddBlocklist(url)
	http.Redirect(w, r, "/?message=Blocklist+added", http.StatusFound)
}

func (s *Server) handleRemoveBlocklist(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	url := r.FormValue("url")
	if url == "" {
		http.Error(w, "URL cannot be empty", http.StatusBadRequest)
		return
	}
	s.adblock.RemoveBlocklist(url)
	http.Redirect(w, r, "/?message=Blocklist+removed", http.StatusFound)
}

func (s *Server) handleAdBlockReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	go s.adblock.UpdateBlocklists() // Run in background
	http.Redirect(w, r, "/?message=Blocklist+update+started", http.StatusFound)
}


func (s *Server) handleHostsReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := s.hosts.Reload(); err != nil {
		http.Error(w, fmt.Sprintf("Failed to reload hosts file: %v", err), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Hosts file reloaded successfully"})
}

const loginPage = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASTRACAT DNS - Login</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; background-color: #f0f2f5; }
        .login-container { background: #fff; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 100%; max-width: 400px; }
        h2 { text-align: center; color: #333; }
        .input-group { margin-bottom: 1rem; }
        .input-group label { display: block; margin-bottom: 0.5rem; color: #555; }
        .input-group input { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { width: 100%; padding: 0.75rem; border: none; border-radius: 4px; background-color: #007bff; color: white; font-size: 1rem; cursor: pointer; }
        .btn:hover { background-color: #0056b3; }
        .error { color: #d93025; text-align: center; margin-top: 1rem; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2>ASTRACAT DNS</h2>
        <form method="post">
            <div class="input-group">
                <label for="username">Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            <div class="input-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            <button type="submit" class="btn">Login</button>
        </form>
        {{if .Error}}
        <p class="error">{{.Error}}</p>
        {{end}}
    </div>
</body>
</html>
`

const statsPage = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASTRACAT DNS - Dashboard</title>
	<meta http-equiv="refresh" content="10">
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; background-color: #f0f2f5; color: #333; }
        .navbar { background-color: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .navbar .logo { font-size: 1.5rem; font-weight: bold; }
        .navbar a { text-decoration: none; color: #007bff; }
		.navbar a:hover { text-decoration: underline; }
        .container { padding: 2rem; }
        .card { background: #fff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 1.5rem; padding: 1.5rem; }
        h1, h2 { color: #333; }
		.stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
        .stat-item { text-align: center; }
        .stat-item .value { font-size: 2.5rem; font-weight: bold; }
        .stat-item .label { color: #666; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; }
        .form-group input { width: 100%; max-width: 400px; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { padding: 0.75rem 1.5rem; border: none; border-radius: 4px; background-color: #007bff; color: white; font-size: 1rem; cursor: pointer; }
        .btn:hover { background-color: #0056b3; }
		.message { padding: 1rem; background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; border-radius: 4px; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="logo">ASTRACAT DNS</div>
        <a href="/logout">Logout</a>
    </div>
    <div class="container">
        <h1>Dashboard</h1>
		{{if .Message}}
		<div class="message">{{.Message}}</div>
		{{end}}
        <div class="card">
            <h2>Statistics</h2>
			<div class="stats-grid">
				<div class="stat-item">
					<div class="value">{{.Queries}}</div>
					<div class="label">Total Queries</div>
				</div>
			</div>
        </div>
        <div class="card">
            <h2>Settings</h2>
            <form action="/change-password" method="post">
                <div class="form-group">
                    <label for="new_password">Change Admin Password</label>
                    <input type="password" id="new_password" name="new_password" minlength="8" required>
                </div>
                <button type="submit" class="btn">Change Password</button>
            </form>
        </div>
		<div class="card">
			<h2>AdBlock Management</h2>
			<div class="form-group">
				<form action="/adblock/add" method="post" style="display: flex; gap: 10px;">
					<input type="url" name="url" placeholder="https://example.com/blocklist.txt" required style="flex-grow: 1;">
					<button type="submit" class="btn">Add Blocklist</button>
				</form>
			</div>
			<div class="form-group">
				<form action="/adblock/reload" method="post">
					<button type="submit" class="btn">Update All Blocklists Now</button>
				</form>
			</div>
			<h4>Current Blocklists:</h4>
			<ul>
				{{range .Blocklists}}
				<li style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 5px;">
					<span>{{.}}</span>
					<form action="/adblock/remove" method="post">
						<input type="hidden" name="url" value="{{.}}">
						<button type="submit" class="btn" style="background-color: #dc3545;">Remove</button>
					</form>
				</li>
				{{end}}
			</ul>
		</div>
    </div>
</body>
</html>
`
