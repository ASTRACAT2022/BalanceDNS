const app = {
    intervalId: null,
    chartInstance: null,

    init: () => {
        app.router();
        window.addEventListener('hashchange', app.router);
        app.loadUserData();
    },

    loadUserData: () => {
        // Placeholder for user profile data
    },

    router: () => {
        // Clear any existing interval when route changes
        if (app.intervalId) {
            clearInterval(app.intervalId);
            app.intervalId = null;
        }

        const hash = window.location.hash || '#dashboard';
        const page = hash.slice(1);
        app.loadPage(page);
        app.updateNav(page);
    },

    updateNav: (page) => {
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === `#${page}`) {
                link.classList.add('active');
            }
        });
    },

    loadPage: async (page) => {
        const content = document.getElementById('content');

        content.innerHTML = '<div class="loading">Loading...</div>';

        switch (page) {
            case 'dashboard':
                await app.renderDashboard(content);
                // Start polling
                app.intervalId = setInterval(app.updateDashboard, 1000);
                break;
            case 'domains':
                content.innerHTML = '<h1>Domains</h1><p>Domain management coming soon...</p>';
                break;
            case 'clients':
                content.innerHTML = '<h1>Clients</h1><p>Client analytics coming soon...</p>';
                break;
            case 'settings':
                await app.renderSettings(content);
                break;
            case 'logs':
                content.innerHTML = '<h1>Logs</h1><p>Real-time logs coming soon...</p>';
                break;
            default:
                content.innerHTML = '<h1>404</h1><p>Page not found</p>';
        }
    },

    renderDashboard: async (container) => {
        try {
            // Initial fetch
            const response = await fetch('/api/metrics');
            if (!response.ok) throw new Error('Failed to fetch metrics');
            const data = await response.json();

            container.innerHTML = `
                <div class="top-bar animate-fade-in">
                    <h1 class="page-title">Dashboard</h1>
                    <div style="display: flex; gap: 1rem; align-items: center;">
                        <span class="status-badge status-low" style="display: flex; align-items: center; gap: 0.5rem;">
                            <span style="width: 8px; height: 8px; background: #10b981; border-radius: 50%; display: inline-block; animation: pulse 2s infinite;"></span>
                            LIVE
                        </span>
                        <input type="text" class="search-bar" placeholder="Search...">
                    </div>
                </div>

                <style>
                @keyframes pulse {
                    0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
                    70% { box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); }
                    100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
                }
                </style>

                <div class="dashboard-grid animate-fade-in">
                    <div class="card">
                        <div class="card-title">Total Queries</div>
                        <div class="card-value" id="val-total-queries">${data.total_queries.toLocaleString()}</div>
                        <div class="card-trend"><i class="ph-trend-up"></i> +8% since last hour</div>
                    </div>
                    <div class="card">
                        <div class="card-title">Blocked</div>
                        <div class="card-value" style="color: #f472b6;" id="val-blocked">${data.blocked_domains.toLocaleString()}</div>
                        <div class="card-trend"><i class="ph-shield-check"></i> Active</div>
                    </div>
                    <div class="card">
                        <div class="card-title">Cache Hit Rate</div>
                        <div class="card-value" style="color: #38bdf8;" id="val-cache-rate">${data.cache_hit_rate.toFixed(2)}%</div>
                         <div class="card-trend"><i class="ph-lightning"></i> Optimized</div>
                    </div>
                     <div class="card">
                        <div class="card-title">QPS</div>
                        <div class="card-value" style="color: #a78bfa;" id="val-qps">${data.qps.toFixed(2)}</div>
                    </div>
                </div>

                <div class="chart-container animate-fade-in">
                    <canvas id="qpsChart"></canvas>
                </div>
                
                <div class="dashboard-grid animate-fade-in">
                    <div class="table-container">
                        <h3><i class="ph-prohibit"></i> Top Blocked Domains</h3>
                         <table id="table-blocked">
                            <thead>
                                <tr>
                                    <th>Domain</th>
                                    <th>Count</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${app.renderBlockedTableRows(data.top_nx_domains)}
                            </tbody>
                        </table>
                    </div>
                     <div class="table-container">
                        <h3><i class="ph-globe"></i> Top Response Codes</h3>
                         <table id="table-codes">
                            <thead>
                                <tr>
                                    <th>Code</th>
                                    <th>Count</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${app.renderCodesTableRows(data.response_codes)}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;

            app.renderChart();

        } catch (err) {
            container.innerHTML = `<div class="error">Error loading dashboard: ${err.message}</div>`;
        }
    },

    renderBlockedTableRows: (domains) => {
        if (!domains || domains.length === 0) return '<tr><td colspan="3">No data available</td></tr>';
        return domains.map(d => `
            <tr>
                <td>${d.domain}</td>
                <td>${d.count}</td>
                <td><span class="status-badge status-high">NXDOMAIN</span></td>
            </tr>
        `).join('');
    },

    renderCodesTableRows: (codes) => {
        if (!codes || codes.length === 0) return '<tr><td colspan="2">No data available</td></tr>';
        return codes.map(d => `
            <tr>
                <td>${d.code}</td>
                <td>${d.count}</td>
            </tr>
        `).join('');
    },

    updateDashboard: async () => {
        try {
            const response = await fetch('/api/metrics');
            if (!response.ok) return; // Silent fail on polling error
            const data = await response.json();

            // Update text values
            const updateText = (id, val) => {
                const el = document.getElementById(id);
                if (el) el.textContent = val;
            };

            updateText('val-total-queries', data.total_queries.toLocaleString());
            updateText('val-blocked', data.blocked_domains.toLocaleString());
            updateText('val-cache-rate', data.cache_hit_rate.toFixed(2) + '%');
            updateText('val-qps', data.qps.toFixed(2));

            // Update tables
            const blockedTableBody = document.querySelector('#table-blocked tbody');
            if (blockedTableBody) blockedTableBody.innerHTML = app.renderBlockedTableRows(data.top_nx_domains);

            const codesTableBody = document.querySelector('#table-codes tbody');
            if (codesTableBody) codesTableBody.innerHTML = app.renderCodesTableRows(data.response_codes);

            // Update Chart
            if (app.chartInstance) {
                const now = new Date();
                const timeLabel = now.getHours().toString().padStart(2, '0') + ':' +
                    now.getMinutes().toString().padStart(2, '0') + ':' +
                    now.getSeconds().toString().padStart(2, '0');

                app.chartInstance.data.labels.push(timeLabel);
                app.chartInstance.data.datasets[0].data.push(data.qps);

                // Keep only last 20 points
                if (app.chartInstance.data.labels.length > 20) {
                    app.chartInstance.data.labels.shift();
                    app.chartInstance.data.datasets[0].data.shift();
                }

                app.chartInstance.update('none'); // 'none' mode for performance
            }

        } catch (e) {
            console.error("Polling error:", e);
        }
    },

    renderChart: () => {
        const ctx = document.getElementById('qpsChart').getContext('2d');
        const gradient = ctx.createLinearGradient(0, 0, 0, 400);
        gradient.addColorStop(0, 'rgba(139, 92, 246, 0.5)');
        gradient.addColorStop(1, 'rgba(139, 92, 246, 0)');

        // Initial empty state or dummy data? Let's start clean
        app.chartInstance = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Queries Per Second',
                    data: [],
                    borderColor: '#8b5cf6',
                    backgroundColor: gradient,
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false, // Turn off init animation for cleaner live updates
                interaction: {
                    intersect: false,
                    mode: 'index',
                },
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#94a3b8' }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { color: '#94a3b8', maxTicksLimit: 6 }
                    }
                }
            }
        });
    },

    renderSettings: async (container) => {
        container.innerHTML = `
            <div class="top-bar animate-fade-in">
                <h1 class="page-title">Settings</h1>
            </div>
            
            <div class="dashboard-grid animate-fade-in">
                 <div class="card">
                    <div class="card-title">Hosts File</div>
                     <p>Manage your local DNS overrides.</p>
                     <!-- <button class="login-btn" onclick="alert('Feature coming in next update')">Edit Hosts</button> -->
                </div>
                 <div class="card">
                    <div class="card-title">AdBlock</div>
                     <p>Manage blocklists and whitelist.</p>
                     <!-- <button class="login-btn" onclick="alert('Feature coming in next update')">Manage Lists</button> -->
                </div>
            </div>
         `;
    }
};

document.addEventListener('DOMContentLoaded', app.init);
