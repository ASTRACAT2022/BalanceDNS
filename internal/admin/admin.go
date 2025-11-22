package admin

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"dns-resolver/internal/config"
	"dns-resolver/internal/metrics"
	"dns-resolver/internal/plugins"
	"dns-resolver/plugins/adblock"
	"dns-resolver/plugins/hosts"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// Server provides an admin web interface.
type Server struct {
	addr         string
	metrics      *metrics.Metrics
	hosts        *hosts.HostsPlugin
	adblock      *adblock.AdBlockPlugin
	pm           *plugins.PluginManager
	username     string
	passwordHash []byte
	sessionToken string
	sessionExpiry time.Time
	configPath   string  // Path to config file
}

// New creates a new admin server.
func New(addr string, m *metrics.Metrics, h *hosts.HostsPlugin, ab *adblock.AdBlockPlugin, pm *plugins.PluginManager) *Server {
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
		pm:           pm,
		username:     username,
		passwordHash: hash,
		configPath:   "config.yaml", // Default config path
	}
}

// Start runs the admin server.
func (s *Server) Start() {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)

	// Protected routes
	mux.Handle("/", s.authMiddleware(http.HandlerFunc(s.handleStats)))
	mux.Handle("/plugins", s.authMiddleware(http.HandlerFunc(s.handlePlugins)))
	mux.Handle("/api/plugins/config", s.authMiddleware(http.HandlerFunc(s.handlePluginConfigUpdate)))
	mux.Handle("/api/metrics", s.authMiddleware(http.HandlerFunc(s.handleApiMetrics)))
	mux.Handle("/change-password", s.authMiddleware(http.HandlerFunc(s.handleChangePassword)))
	mux.Handle("/api/hosts/reload", s.authMiddleware(http.HandlerFunc(s.handleHostsReload)))
	mux.Handle("/api/hosts/content", s.authMiddleware(http.HandlerFunc(s.handleHostsContent)))
	mux.Handle("/hosts/update", s.authMiddleware(http.HandlerFunc(s.handleHostsUpdate)))
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
	
	// Save updated blocklists to config
	if err := s.saveConfig(); err != nil {
		log.Printf("Failed to save config: %v", err)
		// Continue anyway, as the plugin still has the updated list
	}
	
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
	
	// Save updated blocklists to config
	if err := s.saveConfig(); err != nil {
		log.Printf("Failed to save config: %v", err)
		// Continue anyway, as the plugin still has the updated list
	}
	
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


func (s *Server) handleHostsContent(w http.ResponseWriter, r *http.Request) {
	content, err := s.hosts.ReadFileContent()
	if err != nil {
		log.Printf("Failed to read hosts file: %v", err)
		// Return an empty response if file doesn't exist
		content = "# Hosts file not found or empty\n"
	}
	
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(content))
}

func (s *Server) handleHostsUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}
	
	content := r.FormValue("content")
	if content == "" {
		http.Error(w, "Hosts content cannot be empty", http.StatusBadRequest)
		return
	}
	
	// Write the new content to the hosts file
	if err := os.WriteFile(s.hosts.GetFilePath(), []byte(content), 0644); err != nil {
		log.Printf("Failed to write hosts file: %v", err)
		http.Error(w, fmt.Sprintf("Failed to update hosts file: %v", err), http.StatusInternalServerError)
		return
	}
	
	// Reload the hosts plugin to use the new content
	if err := s.hosts.Reload(); err != nil {
		log.Printf("Failed to reload hosts after update: %v", err)
		http.Error(w, fmt.Sprintf("Updated hosts file but failed to reload: %v", err), http.StatusInternalServerError)
		return
	}
	
	http.Redirect(w, r, "/?message=Hosts+file+updated+and+reloaded", http.StatusFound)
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

func (s *Server) handleApiMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	s.metrics.RLock()
	defer s.metrics.RUnlock()

	var topNXDomains []metrics.DomainCount
	s.metrics.TopNXDomains.Range(func(key, value interface{}) bool {
		topNXDomains = append(topNXDomains, metrics.DomainCount{Domain: key.(string), Count: value.(int64)})
		return true
	})

	var topLatencyDomains []metrics.DomainLatency
	s.metrics.TopLatencyDomains.Range(func(key, value interface{}) bool {
		stat := value.(metrics.LatencyStat)
		if stat.Count > 0 {
			avgLatency := stat.TotalLatency.Seconds() * 1000 / float64(stat.Count)
			topLatencyDomains = append(topLatencyDomains, metrics.DomainLatency{Domain: key.(string), AvgLatency: avgLatency})
		}
		return true
	})

	var queryTypes []metrics.TypeCount
	s.metrics.QueryTypes.Range(func(key, value interface{}) bool {
		queryTypes = append(queryTypes, metrics.TypeCount{Type: key.(string), Count: value.(int64)})
		return true
	})

	var responseCodes []metrics.CodeCount
	s.metrics.ResponseCodes.Range(func(key, value interface{}) bool {
		responseCodes = append(responseCodes, metrics.CodeCount{Code: key.(string), Count: value.(int64)})
		return true
	})

	var cacheHitRate float64
	if s.metrics.CacheHits+s.metrics.CacheMisses > 0 {
		cacheHitRate = float64(s.metrics.CacheHits) / float64(s.metrics.CacheHits+s.metrics.CacheMisses) * 100
	}

	data := metrics.DashboardMetrics{
		QPS:               s.metrics.QPS,
		TotalQueries:      s.metrics.GetQueries(),
		BlockedDomains:    s.metrics.BlockedDomains,
		CPUUsage:          s.metrics.CPUUsage,
		MemoryUsage:       s.metrics.MemoryUsage,
		Goroutines:        s.metrics.Goroutines,
		CacheHits:         s.metrics.CacheHits,
		CacheMisses:       s.metrics.CacheMisses,
		CacheHitRate:      cacheHitRate,
		TopNXDomains:      topNXDomains,
		TopLatencyDomains: topLatencyDomains,
		QueryTypes:        queryTypes,
		ResponseCodes:     responseCodes,
	}

	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding metrics to JSON: %v", err)
	}
}

func (s *Server) handlePlugins(w http.ResponseWriter, r *http.Request) {
	message := r.URL.Query().Get("message")
	data := struct {
		Message string
		Plugins []plugins.Plugin
	}{
		Message: message,
		Plugins: s.pm.GetPlugins(),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tpl, _ := template.New("plugins").Parse(pluginsPage)
	tpl.Execute(w, data)
}

func (s *Server) saveConfig() error {
	// Get current config values from plugins
	cfg := config.NewConfig() // This gets defaults, we need to load the actual config file if it exists
	
	// Read existing config file if it exists
	var existingConfigData []byte
	var configExists bool
	if data, err := os.ReadFile(s.configPath); err == nil {
		existingConfigData = data
		configExists = true
	}
	
	// If config file exists, unmarshal it to preserve all other settings
	if configExists {
		if err := yaml.Unmarshal(existingConfigData, cfg); err != nil {
			return fmt.Errorf("failed to unmarshal existing config: %v", err)
		}
	}

	// Update only the adblock list URLs
	cfg.AdBlock.BlocklistURLs = s.adblock.GetBlocklists()

	// Write the updated config back to file
	if err := cfg.Save(s.configPath); err != nil {
		return fmt.Errorf("failed to save config: %v", err)
	}
	
	return nil
}

func (s *Server) handlePluginConfigUpdate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST method is allowed", http.StatusMethodNotAllowed)
		return
	}

	r.ParseForm()
	pluginName := r.FormValue("pluginName")
	plugin := s.pm.GetPlugin(pluginName)
	if plugin == nil {
		http.Error(w, "Plugin not found", http.StatusNotFound)
		return
	}

	config := make(map[string]any)
	for _, field := range plugin.GetConfigFields() {
		config[field.Name] = r.FormValue(field.Name)
	}

	if err := plugin.SetConfig(config); err != nil {
		http.Redirect(w, r, "/plugins?message=Error+updating+config: "+err.Error(), http.StatusFound)
		return
	}

	http.Redirect(w, r, "/plugins?message=Configuration+updated+successfully", http.StatusFound)
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

const pluginsPage = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ASTRACAT DNS - Plugins</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 0; background-color: #f0f2f5; color: #333; }
        .navbar { background-color: #fff; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; }
        .navbar .logo { font-size: 1.5rem; font-weight: bold; }
        .navbar a { text-decoration: none; color: #007bff; }
		.navbar a:hover { text-decoration: underline; }
        .container { padding: 2rem; }
        .card { background: #fff; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); margin-bottom: 1.5rem; padding: 1.5rem; }
        h1, h2 { color: #333; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; }
        .form-group input, .form-group textarea { width: 100%; max-width: 400px; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
        .btn { padding: 0.75rem 1.5rem; border: none; border-radius: 4px; background-color: #007bff; color: white; font-size: 1rem; cursor: pointer; }
        .btn:hover { background-color: #0056b3; }
		.message { padding: 1rem; background-color: #d4edda; color: #155724; border: 1px solid #c3e6cb; border-radius: 4px; margin-bottom: 1rem; }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="logo">ASTRACAT DNS</div>
        <div>
            <a href="/" style="margin-right: 1rem;">Dashboard</a>
            <a href="/logout">Logout</a>
        </div>
    </div>
    <div class="container">
        <h1>Plugin Management</h1>
		{{if .Message}}
		<div class="message">{{.Message}}</div>
		{{end}}
        {{range .Plugins}}
        <div class="card">
            <h2>{{.Name}}</h2>
            <form action="/api/plugins/config" method="post">
                <input type="hidden" name="pluginName" value="{{.Name}}">
                {{range .GetConfigFields}}
                <div class="form-group">
                    <label for="{{.Name}}">{{.Description}}</label>
                    {{if eq .Type "textarea"}}
                    <textarea id="{{.Name}}" name="{{.Name}}" rows="5">{{.Value}}</textarea>
                    {{else}}
                    <input type="{{.Type}}" id="{{.Name}}" name="{{.Name}}" value="{{.Value}}">
                    {{end}}
                </div>
                {{end}}
                <button type="submit" class="btn">Save Configuration</button>
            </form>
        </div>
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
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; 
            margin: 0; 
            background-color: #f5f7fa; 
            color: #333; 
            line-height: 1.6;
        }
        .navbar { 
            background-color: #2c3e50; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
            padding: 1rem 2rem; 
            display: flex; 
            justify-content: space-between; 
            align-items: center; 
        }
        .navbar .logo { 
            font-size: 1.5rem; 
            font-weight: bold; 
            color: #ecf0f1; 
        }
        .navbar a { 
            text-decoration: none; 
            color: #3498db; 
            margin-left: 1.5rem;
        }
        .navbar a:hover { 
            text-decoration: underline; 
        }
        .container { 
            padding: 2rem; 
            max-width: 1600px;
            margin: 0 auto;
        }
        .card { 
            background: #ffffff; 
            border-radius: 10px; 
            box-shadow: 0 4px 15px rgba(0,0,0,0.08); 
            margin-bottom: 1.5rem; 
            padding: 1.5rem; 
        }
        h1, h2, h3 { 
            color: #2c3e50; 
            margin-top: 0;
        }
        .stats-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); 
            gap: 1rem; 
            margin-bottom: 1.5rem;
        }
        .stat-item { 
            text-align: center; 
            padding: 1rem;
            background-color: #f8f9fa;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }
        .stat-item .value { 
            font-size: 2rem; 
            font-weight: bold; 
            color: #2c3e50;
        }
        .stat-item .label { 
            color: #7f8c8d; 
            font-size: 0.9rem;
        }
        .form-group { 
            margin-bottom: 1rem; 
        }
        .form-group label { 
            display: block; 
            margin-bottom: 0.5rem; 
            font-weight: 500;
            color: #2c3e50;
        }
        .form-group input, 
        .form-group textarea { 
            width: 100%; 
            max-width: 100%; 
            padding: 0.75rem; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            box-sizing: border-box; 
            font-size: 1rem;
        }
        .btn { 
            padding: 0.75rem 1.5rem; 
            border: none; 
            border-radius: 4px; 
            background-color: #3498db; 
            color: white; 
            font-size: 1rem; 
            cursor: pointer; 
            transition: background-color 0.3s;
        }
        .btn:hover { 
            background-color: #2980b9; 
        }
        .btn-danger {
            background-color: #e74c3c;
        }
        .btn-danger:hover {
            background-color: #c0392b;
        }
        .message { 
            padding: 1rem; 
            background-color: #d4edda; 
            color: #155724; 
            border: 1px solid #c3e6cb; 
            border-radius: 4px; 
            margin-bottom: 1rem; 
        }
        .metric-sections {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
            gap: 1.5rem;
            margin-bottom: 1.5rem;
        }
        .metric-section {
            min-height: 300px;
        }
        .progress-container {
            margin: 0.5rem 0;
        }
        .progress-bar {
            height: 10px;
            background-color: #ecf0f1;
            border-radius: 5px;
            overflow: hidden;
        }
        .progress-bar-fill {
            height: 100%;
            background-color: #3498db;
            transition: width 0.3s ease;
        }
        .top-domains-list {
            max-height: 300px;
            overflow-y: auto;
            padding: 0.5rem 0;
        }
        .top-domain-item {
            padding: 0.5rem;
            border-bottom: 1px solid #eee;
        }
        .top-domain-item:last-child {
            border-bottom: none;
        }
        .metric-card-large {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 1rem;
            background-color: #f8f9fa;
            border-radius: 8px;
            margin-bottom: 0.5rem;
        }
        .metric-value-large {
            font-size: 1.5rem;
            font-weight: bold;
            color: #2c3e50;
        }
        .loading {
            text-align: center;
            padding: 1rem;
            color: #7f8c8d;
        }
        .error-message {
            color: #e74c3c;
            padding: 1rem;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="navbar">
        <div class="logo">ASTRACAT DNS Resolver</div>
        <a href="/logout">Logout</a>
    </div>
    <div class="container">
        <h1>Dashboard</h1>
        {{if .Message}}
        <div class="message">{{.Message}}</div>
        {{end}}
        
        <!-- Main Statistics -->
        <div class="card">
            <h2>System Statistics</h2>
            <div class="stats-grid">
                <div class="stat-item">
                    <div class="value" id="total-queries">{{.Queries}}</div>
                    <div class="label">Total Queries</div>
                </div>
                <div class="stat-item">
                    <div class="value" id="qps">0.00</div>
                    <div class="label">Queries Per Second</div>
                </div>
                <div class="stat-item">
                    <div class="value" id="blocked-domains">0</div>
                    <div class="label">Blocked Domains</div>
                </div>
                <div class="stat-item">
                    <div class="value" id="cache-hit-rate">0.00%</div>
                    <div class="label">Cache Hit Rate</div>
                </div>
                <div class="stat-item">
                    <div class="value" id="cpu-usage">0.00%</div>
                    <div class="label">CPU Usage</div>
                </div>
                <div class="stat-item">
                    <div class="value" id="memory-usage">0.00%</div>
                    <div class="label">Memory Usage</div>
                </div>
                <div class="stat-item">
                    <div class="value" id="goroutines">0</div>
                    <div class="label">Goroutines</div>
                </div>
                <div class="stat-item">
                    <div class="value" id="cache-hits">0</div>
                    <div class="label">Cache Hits</div>
                </div>
                <div class="stat-item">
                    <div class="value" id="cache-misses">0</div>
                    <div class="label">Cache Misses</div>
                </div>
            </div>
            <div style="width: 100%; height: 300px; margin-top: 1rem;">
                <canvas id="qpsChart"></canvas>
            </div>
        </div>
        
        <!-- System Resources and Performance -->
        <div class="metric-sections">
            <div class="card metric-section">
                <h2>System Resources</h2>
                <div class="progress-container">
                    <div class="metric-card-large">
                        <span>CPU Usage</span>
                        <div class="metric-value-large" id="cpu-usage-large">0.00%</div>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-bar-fill" id="cpu-progress" style="width: 0%"></div>
                    </div>
                </div>
                <div class="progress-container">
                    <div class="metric-card-large">
                        <span>Memory Usage</span>
                        <div class="metric-value-large" id="memory-usage-large">0.00%</div>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-bar-fill" id="memory-progress" style="width: 0%"></div>
                    </div>
                </div>
                <div class="progress-container">
                    <div class="metric-card-large">
                        <span>Cache Hit Rate</span>
                        <div class="metric-value-large" id="cache-hit-rate-large">0.00%</div>
                    </div>
                    <div class="progress-bar">
                        <div class="progress-bar-fill" id="cache-progress" style="width: 0%"></div>
                    </div>
                </div>
            </div>

            <div class="card metric-section">
                <h2>Performance Metrics</h2>
                <div class="metric-card-large">
                    <span>Goroutines</span>
                    <div class="metric-value-large" id="goroutines-large">0</div>
                </div>
                <div class="metric-card-large">
                    <span>Cache Hits</span>
                    <div class="metric-value-large" id="cache-hits-large">0</div>
                </div>
                <div class="metric-card-large">
                    <span>Cache Misses</span>
                    <div class="metric-value-large" id="cache-misses-large">0</div>
                </div>
                <div class="metric-card-large">
                    <span>QPS</span>
                    <div class="metric-value-large" id="qps-large">0.00</div>
                </div>
            </div>
        </div>
        
        
        <!-- Query Types and Response Codes -->
        <div class="metric-sections">
            <div class="card">
                <h2>Query Types</h2>
                <div class="top-domains-list" id="query-types">
                    <div class="loading">Loading...</div>
                </div>
            </div>
            <div class="card">
                <h2>Response Codes</h2>
                <div class="top-domains-list" id="response-codes">
                    <div class="loading">Loading...</div>
                </div>
            </div>
        </div>

        <!-- Settings and Management -->
        <div class="card">
            <h2>Settings & Management</h2>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem;">
                <div>
                    <h3>Change Password</h3>
                    <form action="/change-password" method="post">
                        <div class="form-group">
                            <label for="new_password">New Admin Password (min 8 chars)</label>
                            <input type="password" id="new_password" name="new_password" minlength="8" required>
                        </div>
                        <button type="submit" class="btn">Change Password</button>
                    </form>
                </div>
                
                <div>
                    <h3>AdBlock Management</h3>
                    <div class="form-group">
                        <form action="/adblock/add" method="post">
                            <label>Add Blocklist URL</label>
                            <input type="url" name="url" placeholder="https://example.com/blocklist.txt" required>
                            <button type="submit" class="btn" style="margin-top: 0.5rem;">Add Blocklist</button>
                        </form>
                    </div>
                    <div class="form-group">
                        <form action="/adblock/reload" method="post">
                            <button type="submit" class="btn">Update All Blocklists Now</button>
                        </form>
                    </div>
                </div>
                
                <div>
                    <h3>Hosts Management</h3>
                    <form action="/hosts/update" method="post">
                        <div class="form-group">
                            <label>Update Hosts File</label>
                            <textarea id="content" name="content" rows="3" placeholder="Enter hosts content">127.0.0.1 localhost
127.0.0.1 example.com</textarea>
                        </div>
                        <button type="submit" class="btn">Update Hosts File</button>
                    </form>
                    <div class="form-group" style="margin-top: 0.5rem;">
                        <form action="/api/hosts/reload" method="post">
                            <button type="submit" class="btn">Reload Hosts File</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Current Blocklists -->
        <div class="card">
            <h2>Current Blocklists</h2>
            <ul id="current-blocklists">
                {{range .Blocklists}}
                <li style="display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 0; border-bottom: 1px solid #eee;">
                    <span style="word-break: break-all; flex-grow: 1;">{{.}}</span>
                    <form action="/adblock/remove" method="post" style="margin-left: 1rem;">
                        <input type="hidden" name="url" value="{{.}}">
                        <button type="submit" class="btn btn-danger">Remove</button>
                    </form>
                </li>
                {{else}}
                <li>No blocklists configured</li>
                {{end}}
            </ul>
        </div>
    </div>
    
    <script>
        // Load current hosts file content on page load
        window.onload = function() {
            fetch('/api/hosts/content')
            .then(response => {
                if (response.ok) {
                    return response.text();
                }
                return "# Failed to load hosts content";
            })
            .then(content => {
                const contentElement = document.getElementById('content');
                if (contentElement) {
                    contentElement.value = content;
                }
            })
            .catch(error => {
                console.error('Error loading hosts content:', error);
            });
        };
    </script>
    
    <script>
        // Initialize charts
        const qpsCtx = document.getElementById('qpsChart').getContext('2d');
        const qpsChart = new Chart(qpsCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Queries Per Second',
                    data: [],
                    borderColor: '#3498db',
                    backgroundColor: 'rgba(52, 152, 219, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    },
                    x: {
                        grid: {
                            color: 'rgba(0, 0, 0, 0.05)'
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: true,
                        position: 'top',
                    },
                    tooltip: {
                        enabled: true,
                        mode: 'index',
                        intersect: false
                    }
                }
            }
        });

        // Update metrics function with better error handling
        function updateMetrics() {
            fetch('/api/metrics')
                .timeout = 5000; // 5 second timeout
                
            fetch('/api/metrics', { 
                method: 'GET',
                cache: 'no-cache',
                headers: {
                    'Cache-Control': 'no-cache'
                }
            })
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                // Update main statistics
                document.getElementById('total-queries').innerText = formatNumber(data.total_queries || 0);
                document.getElementById('qps').innerText = (data.qps || 0).toFixed(2);
                document.getElementById('blocked-domains').innerText = formatNumber(data.blocked_domains || 0);
                document.getElementById('cache-hit-rate').innerText = (data.cache_hit_rate || 0).toFixed(2) + '%';
                document.getElementById('cpu-usage').innerText = (data.cpu_usage || 0).toFixed(2) + '%';
                document.getElementById('memory-usage').innerText = (data.memory_usage || 0).toFixed(2) + '%';
                document.getElementById('goroutines').innerText = data.goroutines || 0;
                document.getElementById('cache-hits').innerText = formatNumber(data.cache_hits || 0);
                document.getElementById('cache-misses').innerText = formatNumber(data.cache_misses || 0);
                
                // Update large display values
                document.getElementById('qps-large').innerText = (data.qps || 0).toFixed(2);
                document.getElementById('cpu-usage-large').innerText = (data.cpu_usage || 0).toFixed(2) + '%';
                document.getElementById('memory-usage-large').innerText = (data.memory_usage || 0).toFixed(2) + '%';
                document.getElementById('cache-hit-rate-large').innerText = (data.cache_hit_rate || 0).toFixed(2) + '%';
                document.getElementById('goroutines-large').innerText = data.goroutines || 0;
                document.getElementById('cache-hits-large').innerText = formatNumber(data.cache_hits || 0);
                document.getElementById('cache-misses-large').innerText = formatNumber(data.cache_misses || 0);
                
                // Update progress bars
                document.getElementById('cpu-progress').style.width = Math.min(100, data.cpu_usage || 0) + '%';
                document.getElementById('memory-progress').style.width = Math.min(100, data.memory_usage || 0) + '%';
                document.getElementById('cache-progress').style.width = Math.min(100, data.cache_hit_rate || 0) + '%';
                
                // Update top queried domains
                updateList('top-queried-domains', data.top_queried_domains || [], 'domain', 'count');
                
                // Update top NX domains
                updateList('top-nx-domains', data.top_nx_domains || [], 'domain', 'count');
                
                // Update query types
                updateList('query-types', data.query_types || [], 'type', 'count');
                
                // Update response codes
                updateList('response-codes', data.response_codes || [], 'code', 'count');
                
                // Update chart with new data point
                const now = new Date();
                qpsChart.data.labels.push(now.toLocaleTimeString());
                qpsChart.data.datasets[0].data.push(data.qps || 0);
                
                // Keep only the last 60 points
                if (qpsChart.data.labels.length > 60) {
                    qpsChart.data.labels.shift();
                    qpsChart.data.datasets[0].data.shift();
                }
                
                qpsChart.update();
                
                // Update status indicators
                document.getElementById('total-queries').style.color = '#27ae60';
                document.getElementById('qps').style.color = '#27ae60';
            })
            .catch(error => {
                console.error('Error fetching metrics:', error);
                showErrorMessage('Failed to load metrics. Will retry automatically...');
                
                // Keep trying to update even if there's an error
                setTimeout(updateMetrics, 5000); // Retry after 5 seconds
            });
        }
        
        // Helper function to format large numbers
        function formatNumber(num) {
            return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
        }
        
        // Helper function to update list items
        function updateList(elementId, items, nameField, countField) {
            const container = document.getElementById(elementId);
            if (!container) return;
            
            if (!items || items.length === 0) {
                container.innerHTML = '<div class="loading">No data available</div>';
                return;
            }
            
            let html = '';
            items.slice(0, 20).forEach(item => {
                html += '<div class="top-domain-item">' +
                        '<strong>' + item[nameField] + '</strong> - ' + formatNumber(item[countField] || 0) +
                        '</div>';
            });
            
            if (items.length > 20) {
                html += '<div class="loading">... and ' + (items.length - 20) + ' more</div>';
            }
            
            container.innerHTML = html;
        }
        
        // Show error message function
        function showErrorMessage(message) {
            // Only show error if no other error is currently displayed
            if (!document.querySelector('.error-message')) {
                const errorDiv = document.createElement('div');
                errorDiv.className = 'error-message';
                errorDiv.textContent = message;
                errorDiv.style.position = 'fixed';
                errorDiv.style.top = '10px';
                errorDiv.style.right = '10px';
                errorDiv.style.zIndex = '1000';
                errorDiv.style.backgroundColor = '#fadbd8';
                errorDiv.style.border = '1px solid #e74c3c';
                errorDiv.style.borderRadius = '4px';
                errorDiv.style.padding = '10px';
                
                document.body.appendChild(errorDiv);
                
                // Remove error after 5 seconds
                setTimeout(() => {
                    if (errorDiv.parentNode) {
                        errorDiv.parentNode.removeChild(errorDiv);
                    }
                }, 5000);
            }
        }

        // Update metrics every 2 seconds with error handling
        setInterval(updateMetrics, 2000);
        updateMetrics(); // Initial call
    </script>
</body>
</html>
`
