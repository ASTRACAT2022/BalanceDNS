const app = {
  state: {
    dashboard: null,
    config: null,
    plugins: [],
    hosts: null,
    policy: null,
  },
  activeRoute: "dashboard",
  poller: null,

  init() {
    this.bindShell();
    this.route();
    window.addEventListener("hashchange", () => this.route());
  },

  bindShell() {
    document.querySelectorAll(".nav-link").forEach((button) => {
      button.addEventListener("click", () => {
        const route = button.dataset.route || "dashboard";
        window.location.hash = route;
      });
    });

    document.getElementById("refreshPage").addEventListener("click", () => this.route(true));
    document.getElementById("reloadResolver").addEventListener("click", () => this.runAction("/api/control/reload", "Resolver reloaded"));
    document.getElementById("clearCache").addEventListener("click", () => this.runAction("/api/control/cache/clear", "Cache cleared"));
  },

  async route(force = false) {
    const route = (window.location.hash || "#dashboard").slice(1);
    this.activeRoute = route;
    this.stopPolling();
    this.updateNav(route);
    this.updatePageMeta(route);

    if (!force) {
      this.setView(this.renderLoading());
    }

    try {
      switch (route) {
        case "dashboard":
          await this.renderDashboard();
          this.startPolling(() => this.renderDashboard(true), 10000);
          break;
        case "config":
          await this.renderConfig();
          break;
        case "plugins":
          await this.renderPlugins();
          break;
        case "dns":
          await this.renderHosts();
          break;
        case "policy":
          await this.renderPolicy();
          break;
        default:
          window.location.hash = "dashboard";
      }
    } catch (error) {
      this.setView(this.renderError(error));
      this.flash(error.message || "Не удалось загрузить данные", "error");
    }
  },

  updateNav(route) {
    document.querySelectorAll(".nav-link").forEach((button) => {
      button.classList.toggle("active", button.dataset.route === route);
    });
  },

  updatePageMeta(route) {
    const titles = {
      dashboard: ["Мониторинг", "Живая телеметрия, история нагрузки и состояние DNS control plane"],
      config: ["Конфиг", "Просмотр и редактирование основного config.yaml"],
      plugins: ["Плагины", "Управление runtime-плагинами и их настройками"],
      dns: ["DNS / Hosts", "Локальные host overrides, источник данных и редактирование записей"],
      policy: ["Policy Manager", "Гибкая настройка block, rewrite и load balancing правил"],
    };
    const [title, eyebrow] = titles[route] || titles.dashboard;
    document.getElementById("pageTitle").textContent = title;
    document.getElementById("pageEyebrow").textContent = eyebrow;
  },

  setView(html) {
    document.getElementById("app").innerHTML = html;
  },

  renderLoading() {
    return `<div class="empty-state"><div class="spinner"></div><p>Загружаем данные control plane...</p></div>`;
  },

  renderError(error) {
    return `<div class="empty-state error-state"><h3>Не удалось загрузить данные</h3><p>${this.escapeHtml(error.message || String(error))}</p></div>`;
  },

  async renderDashboard(isBackgroundRefresh = false) {
    const data = await this.api("/api/dashboard");
    this.state.dashboard = data;

    const metrics = data.metrics;
    const statusText = `${data.system.resolver_type || "resolver"} · ${data.system.listen_addr || "n/a"}`;
    const history24 = this.renderMetricChart(metrics.history_24h, "qps", { stroke: "#53e3c2", fill: "rgba(83, 227, 194, 0.16)" }, "QPS / 24h");
    const history7 = this.renderMetricChart(metrics.history_7d, "cache_hit_rate", { stroke: "#ffbf69", fill: "rgba(255, 191, 105, 0.18)" }, "Cache Hit / 7d");

    document.getElementById("sidebarStatus").textContent = statusText;

    const html = `
      <section class="hero-panel">
        <div>
          <div class="eyebrow">Live status</div>
          <h2>Нагрузка, кэш и DNS-активность за 24 часа и 7 дней</h2>
          <p class="hero-copy">Панель показывает текущий QPS, эффективность кэша, системные ресурсы, сетевую активность и топ домены без выхода из control plane.</p>
        </div>
        <div class="hero-badges">
          <span class="pill ${metrics.qps > 0 ? "pill-live" : ""}">QPS ${this.formatNumber(metrics.qps, 2)}</span>
          <span class="pill">Cache ${this.formatNumber(metrics.cache_hit_rate, 1)}%</span>
          <span class="pill">CPU ${this.formatNumber(metrics.cpu_usage, 1)}%</span>
        </div>
      </section>

      <section class="stat-grid">
        ${this.renderStatCard("Total Queries", this.formatCompact(metrics.total_queries), "За всё время работы сервиса")}
        ${this.renderStatCard("Blocked Domains", this.formatCompact(metrics.blocked_domains), "Сработало через adblock и policy")}
        ${this.renderStatCard("Cache Hit Rate", `${this.formatNumber(metrics.cache_hit_rate, 1)}%`, `${this.formatCompact(metrics.cache_hits)} hits / ${this.formatCompact(metrics.cache_misses)} misses`)}
        ${this.renderStatCard("Runtime QPS", this.formatNumber(metrics.qps, 2), "Актуальное значение за последнюю секунду")}
        ${this.renderStatCard("CPU / Memory", `${this.formatNumber(metrics.cpu_usage, 1)}% / ${this.formatNumber(metrics.memory_usage, 1)}%`, `${metrics.goroutines} goroutines`)}
        ${this.renderStatCard("Network IO", `${this.formatBytes(metrics.network_recv_bytes)} in`, `${this.formatBytes(metrics.network_sent_bytes)} out`)}
      </section>

      <section class="chart-grid">
        <article class="panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">24 часа</div>
              <h3>QPS History</h3>
            </div>
            <div class="mini-meta">${metrics.history_24h.length} точек</div>
          </div>
          ${history24}
        </article>
        <article class="panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">7 дней</div>
              <h3>Cache Efficiency</h3>
            </div>
            <div class="mini-meta">uptime ${this.formatDuration(metrics.uptime_seconds)}</div>
          </div>
          ${history7}
        </article>
      </section>

      <section class="detail-grid">
        <article class="panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">Top domains</div>
              <h3>Самые частые запросы</h3>
            </div>
          </div>
          ${this.renderDomainTable(metrics.top_queried_domains, "Домен", "Запросы")}
        </article>
        <article class="panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">Blocked / NX</div>
              <h3>Проблемные домены</h3>
            </div>
          </div>
          ${this.renderDomainTable(metrics.top_nx_domains, "Домен", "NXDOMAIN")}
        </article>
        <article class="panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">Response codes</div>
              <h3>Коды ответов</h3>
            </div>
          </div>
          ${this.renderCodeTable(metrics.response_codes)}
        </article>
        <article class="panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">Latency</div>
              <h3>Домены с высокой задержкой</h3>
            </div>
          </div>
          ${this.renderLatencyTable(metrics.top_latency_domains)}
        </article>
      </section>

      <section class="split-grid">
        <article class="panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">Runtime overview</div>
              <h3>Системный срез</h3>
            </div>
          </div>
          <div class="kv-grid">
            ${this.renderKV("Listen", data.system.listen_addr)}
            ${this.renderKV("Resolver", data.system.resolver_type)}
            ${this.renderKV("Metrics", data.system.metrics_addr)}
            ${this.renderKV("Prometheus", data.system.prometheus_enabled ? "on" : "off")}
            ${this.renderKV("Cache path", data.system.cache_path)}
            ${this.renderKV("Workers", String(data.system.resolver_workers || "auto"))}
            ${this.renderKV("Max QPS/IP", String(data.system.max_qps_per_ip))}
            ${this.renderKV("Inflight", String(data.system.max_global_inflight))}
          </div>
        </article>
        <article class="panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">Runtime modules</div>
              <h3>Плагины и подсистемы</h3>
            </div>
          </div>
          <div class="plugin-list">
            ${data.plugins.map((plugin) => `
              <div class="plugin-row">
                <div>
                  <strong>${this.escapeHtml(plugin.name)}</strong>
                  <p>${this.escapeHtml(plugin.description)}</p>
                </div>
                <span class="status-dot ${plugin.enabled ? "status-on" : "status-off"}">${plugin.enabled ? "active" : "disabled"}</span>
              </div>
            `).join("") || `<p class="muted-copy">Активные плагины не зарегистрированы.</p>`}
          </div>
        </article>
      </section>
    `;

    if (!isBackgroundRefresh || this.activeRoute === "dashboard") {
      this.setView(html);
    }
  },

  async renderConfig() {
    const data = await this.api("/api/config");
    this.state.config = data;

    this.setView(`
      <section class="split-grid">
        <article class="panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">Summary</div>
              <h3>Ключевые параметры сервера</h3>
            </div>
          </div>
          <div class="kv-grid">
            ${Object.entries(data.summary).map(([key, value]) => this.renderKV(this.labelize(key), String(value))).join("")}
          </div>
        </article>
        <article class="panel accent-panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">Safe editing</div>
              <h3>Полный <code>config.yaml</code></h3>
            </div>
          </div>
          <p class="muted-copy">После сохранения runtime-часть панели синхронизирует policy и plugin-настройки. Изменения сокетов, адресов и enabled-флагов могут потребовать рестарт процесса.</p>
        </article>
      </section>

      <section class="panel">
        <form id="configForm" class="stack-form">
          <label class="field">
            <span>Конфигурация YAML</span>
            <textarea name="raw" class="code-area" spellcheck="false">${this.escapeHtml(data.raw)}</textarea>
          </label>
          <div class="form-actions">
            <button type="submit" class="primary-button">Сохранить config.yaml</button>
          </div>
        </form>
      </section>
    `);

    document.getElementById("configForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const raw = event.currentTarget.elements.raw.value;
      const result = await this.api("/api/config", {
        method: "PUT",
        body: JSON.stringify({ raw }),
      });
      this.flash(result.message + (result.requires_restart ? " Требуется рестарт процесса для части настроек." : ""), "success");
      await this.renderConfig();
    });
  },

  async renderPlugins() {
    const plugins = await this.api("/api/plugins");
    this.state.plugins = plugins;

    this.setView(`
      <section class="stack-layout">
        ${plugins.map((plugin) => this.renderPluginCard(plugin)).join("") || `<div class="empty-state"><p>Плагины не зарегистрированы.</p></div>`}
      </section>
    `);

    document.querySelectorAll(".plugin-form").forEach((form) => {
      form.addEventListener("submit", async (event) => {
        event.preventDefault();
        const pluginName = form.dataset.plugin;
        const config = {};

        form.querySelectorAll("[data-field]").forEach((input) => {
          const key = input.dataset.field;
          if (input.type === "checkbox") {
            config[key] = input.checked;
          } else {
            config[key] = input.value;
          }
        });

        await this.api(`/api/plugins/${encodeURIComponent(pluginName)}`, {
          method: "PUT",
          body: JSON.stringify({ config }),
        });
        this.flash(`Настройки плагина ${pluginName} сохранены`, "success");
        await this.renderPlugins();
      });
    });
  },

  async renderHosts() {
    const data = await this.api("/api/hosts");
    this.state.hosts = data;

    this.setView(`
      <section class="split-grid">
        <article class="panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">Hosts source</div>
              <h3>Управление локальными DNS override</h3>
            </div>
          </div>
          <div class="kv-grid">
            ${this.renderKV("Enabled", data.enabled ? "true" : "false")}
            ${this.renderKV("Local path", data.file_path)}
            ${this.renderKV("Remote URL", data.hosts_url || "not set")}
            ${this.renderKV("Update interval", data.update_interval)}
          </div>
        </article>
        <article class="panel accent-panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">DNS data</div>
              <h3>Редактирование hosts файла</h3>
            </div>
          </div>
          <p class="muted-copy">Сюда можно добавлять A/AAAA override-записи, локальные зоны и временные hostname-маршруты. После сохранения файл перезагружается автоматически.</p>
        </article>
      </section>

      <section class="panel">
        <form id="hostsForm" class="stack-form">
          <div class="triple-grid">
            ${this.renderInputField("Путь к hosts", "file_path", data.file_path)}
            ${this.renderInputField("Remote URL", "hosts_url", data.hosts_url)}
            ${this.renderInputField("Интервал обновления", "update_interval", data.update_interval)}
          </div>
          <label class="field">
            <span>Содержимое файла</span>
            <textarea name="content" class="code-area" spellcheck="false">${this.escapeHtml(data.content)}</textarea>
          </label>
          <div class="form-actions">
            <button type="submit" class="primary-button">Сохранить DNS / Hosts</button>
          </div>
        </form>
      </section>
    `);

    document.getElementById("hostsForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const payload = {
        file_path: form.elements.file_path.value,
        hosts_url: form.elements.hosts_url.value,
        update_interval: form.elements.update_interval.value,
        content: form.elements.content.value,
      };
      const result = await this.api("/api/hosts", {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      this.flash(result.message, "success");
      await this.renderHosts();
    });
  },

  async renderPolicy() {
    const data = await this.api("/api/policy");
    this.state.policy = data;

    this.setView(`
      <section class="split-grid">
        <article class="panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">Policy engine</div>
              <h3>Block, rewrite и load balancing правила</h3>
            </div>
          </div>
          <div class="toggle-row">
            <label class="toggle">
              <input id="policyEnabled" type="checkbox" ${data.enabled ? "checked" : ""}>
              <span>Policy engine enabled</span>
            </label>
            <span class="status-dot ${data.runtime_applied ? "status-on" : "status-warn"}">${data.runtime_applied ? "runtime applied" : "restart may be required"}</span>
          </div>
        </article>
        <article class="panel accent-panel">
          <div class="panel-head">
            <div>
              <div class="eyebrow">Flexible control</div>
              <h3>Менеджер политик как на enterprise edge</h3>
            </div>
          </div>
          <p class="muted-copy">Можно блокировать домены, переписывать ответы и развешивать round-robin / weighted балансировку по A и AAAA записям.</p>
        </article>
      </section>

      <section class="panel">
        <form id="policyForm" class="stack-form">
          <label class="field">
            <span>Blocked domains (по одному домену на строку)</span>
            <textarea name="blocked_domains" class="code-area compact-area">${this.escapeHtml((data.blocked_domains || []).join("\n"))}</textarea>
          </label>

          <div class="editor-block">
            <div class="editor-head">
              <h3>Rewrite Rules</h3>
              <button type="button" id="addRewriteRule" class="ghost-button">Добавить rewrite</button>
            </div>
            <div id="rewriteRules" class="rule-stack">
              ${(data.rewrite_rules || []).map((rule) => this.renderRewriteRule(rule)).join("")}
            </div>
          </div>

          <div class="editor-block">
            <div class="editor-head">
              <h3>Load Balancers</h3>
              <button type="button" id="addLoadBalancer" class="ghost-button">Добавить balancer</button>
            </div>
            <div id="loadBalancers" class="rule-stack">
              ${(data.load_balancers || []).map((rule) => this.renderLoadBalancer(rule)).join("")}
            </div>
          </div>

          <div class="form-actions">
            <button type="submit" class="primary-button">Сохранить policy</button>
          </div>
        </form>
      </section>
    `);

    document.getElementById("addRewriteRule").addEventListener("click", () => {
      document.getElementById("rewriteRules").insertAdjacentHTML("beforeend", this.renderRewriteRule({ domain: "", type: "A", value: "", ttl: 60 }));
    });

    document.getElementById("addLoadBalancer").addEventListener("click", () => {
      document.getElementById("loadBalancers").insertAdjacentHTML("beforeend", this.renderLoadBalancer({ domain: "", type: "A", strategy: "round_robin", ttl: 30, targets: [] }));
    });

    this.bindRuleRemoval("rewriteRules");
    this.bindRuleRemoval("loadBalancers");

    document.getElementById("policyForm").addEventListener("submit", async (event) => {
      event.preventDefault();
      const form = event.currentTarget;
      const payload = {
        enabled: document.getElementById("policyEnabled").checked,
        blocked_domains: this.linesToArray(form.elements.blocked_domains.value),
        rewrite_rules: this.collectRewriteRules(),
        load_balancers: this.collectLoadBalancers(),
      };
      await this.api("/api/policy", {
        method: "PUT",
        body: JSON.stringify(payload),
      });
      this.flash("Policy manager сохранён", "success");
      await this.renderPolicy();
    });
  },

  bindRuleRemoval(containerId) {
    document.getElementById(containerId).addEventListener("click", (event) => {
      const button = event.target.closest("[data-remove-rule]");
      if (!button) {
        return;
      }
      button.closest(".rule-card")?.remove();
    });
  },

  collectRewriteRules() {
    return Array.from(document.querySelectorAll("#rewriteRules .rule-card")).map((card) => ({
      domain: card.querySelector('[name="domain"]').value.trim(),
      type: card.querySelector('[name="type"]').value.trim(),
      value: card.querySelector('[name="value"]').value.trim(),
      ttl: Number(card.querySelector('[name="ttl"]').value || 0),
    })).filter((rule) => rule.domain && rule.type && rule.value);
  },

  collectLoadBalancers() {
    return Array.from(document.querySelectorAll("#loadBalancers .rule-card")).map((card) => ({
      domain: card.querySelector('[name="domain"]').value.trim(),
      type: card.querySelector('[name="type"]').value.trim(),
      strategy: card.querySelector('[name="strategy"]').value.trim(),
      ttl: Number(card.querySelector('[name="ttl"]').value || 0),
      targets: this.linesToTargets(card.querySelector('[name="targets"]').value),
    })).filter((rule) => rule.domain && rule.type && rule.targets.length > 0);
  },

  renderPluginCard(plugin) {
    return `
      <section class="panel">
        <div class="panel-head">
          <div>
            <div class="eyebrow">Plugin</div>
            <h3>${this.escapeHtml(plugin.name)}</h3>
          </div>
          <span class="status-dot ${plugin.enabled ? "status-on" : "status-off"}">${plugin.enabled ? "enabled" : "disabled"}</span>
        </div>
        <p class="muted-copy">${this.escapeHtml(plugin.description || "")}</p>
        <form class="plugin-form stack-form" data-plugin="${this.escapeHtml(plugin.name)}">
          <div class="double-grid">
            ${plugin.fields.map((field) => this.renderPluginField(field)).join("")}
          </div>
          <div class="form-actions">
            <button type="submit" class="primary-button">Сохранить плагин</button>
          </div>
        </form>
      </section>
    `;
  },

  renderPluginField(field) {
    const label = this.escapeHtml(field.description || field.name);
    const name = this.escapeHtml(field.name);
    if (field.type === "boolean") {
      return `
        <label class="field checkbox-field">
          <span>${label}</span>
          <input data-field="${name}" type="checkbox" ${field.value ? "checked" : ""}>
        </label>
      `;
    }

    if (field.type === "textarea") {
      return `
        <label class="field full-span">
          <span>${label}</span>
          <textarea data-field="${name}" class="code-area compact-area">${this.escapeHtml(field.value || "")}</textarea>
        </label>
      `;
    }

    return `
      <label class="field">
        <span>${label}</span>
        <input data-field="${name}" type="text" value="${this.escapeHtml(field.value ?? "")}">
      </label>
    `;
  },

  renderRewriteRule(rule) {
    return `
      <article class="rule-card">
        <div class="rule-card-head">
          <strong>Rewrite</strong>
          <button type="button" class="icon-button" data-remove-rule>Удалить</button>
        </div>
        <div class="double-grid">
          ${this.renderInlineField("Domain", "domain", rule.domain || "")}
          ${this.renderInlineField("Type", "type", rule.type || "A")}
          ${this.renderInlineField("Value", "value", rule.value || "")}
          ${this.renderInlineField("TTL", "ttl", rule.ttl || 60, "number")}
        </div>
      </article>
    `;
  },

  renderLoadBalancer(rule) {
    const targets = (rule.targets || []).map((target) => `${target.value} ${target.weight || 1}`).join("\n");
    return `
      <article class="rule-card">
        <div class="rule-card-head">
          <strong>Load Balancer</strong>
          <button type="button" class="icon-button" data-remove-rule>Удалить</button>
        </div>
        <div class="double-grid">
          ${this.renderInlineField("Domain", "domain", rule.domain || "")}
          ${this.renderInlineField("Type", "type", rule.type || "A")}
          ${this.renderInlineField("Strategy", "strategy", rule.strategy || "round_robin")}
          ${this.renderInlineField("TTL", "ttl", rule.ttl || 30, "number")}
          <label class="field full-span">
            <span>Targets (<code>IP weight</code> на строку)</span>
            <textarea name="targets" class="code-area compact-area">${this.escapeHtml(targets)}</textarea>
          </label>
        </div>
      </article>
    `;
  },

  renderInlineField(label, name, value, type = "text") {
    return `
      <label class="field">
        <span>${this.escapeHtml(label)}</span>
        <input name="${this.escapeHtml(name)}" type="${type}" value="${this.escapeHtml(value)}">
      </label>
    `;
  },

  renderInputField(label, name, value) {
    return `
      <label class="field">
        <span>${this.escapeHtml(label)}</span>
        <input name="${this.escapeHtml(name)}" type="text" value="${this.escapeHtml(value || "")}">
      </label>
    `;
  },

  renderStatCard(label, value, meta) {
    return `
      <article class="stat-card">
        <div class="eyebrow">${this.escapeHtml(label)}</div>
        <div class="stat-value">${this.escapeHtml(value)}</div>
        <div class="stat-meta">${this.escapeHtml(meta)}</div>
      </article>
    `;
  },

  renderDomainTable(items, headerA, headerB) {
    if (!items || items.length === 0) {
      return `<div class="table-empty">Данные пока не накоплены.</div>`;
    }
    return `
      <table class="data-table">
        <thead><tr><th>${headerA}</th><th>${headerB}</th></tr></thead>
        <tbody>
          ${items.map((item) => `<tr><td>${this.escapeHtml(item.domain)}</td><td>${this.formatCompact(item.count)}</td></tr>`).join("")}
        </tbody>
      </table>
    `;
  },

  renderCodeTable(items) {
    if (!items || items.length === 0) {
      return `<div class="table-empty">Ответы ещё не собраны.</div>`;
    }
    return `
      <table class="data-table">
        <thead><tr><th>Code</th><th>Count</th></tr></thead>
        <tbody>
          ${items.map((item) => `<tr><td>${this.escapeHtml(item.code)}</td><td>${this.formatCompact(item.count)}</td></tr>`).join("")}
        </tbody>
      </table>
    `;
  },

  renderLatencyTable(items) {
    if (!items || items.length === 0) {
      return `<div class="table-empty">Задержка пока не накоплена.</div>`;
    }
    return `
      <table class="data-table">
        <thead><tr><th>Domain</th><th>Avg latency</th></tr></thead>
        <tbody>
          ${items.map((item) => `<tr><td>${this.escapeHtml(item.domain)}</td><td>${this.formatNumber(item.avg_latency, 2)} ms</td></tr>`).join("")}
        </tbody>
      </table>
    `;
  },

  renderKV(label, value) {
    return `
      <div class="kv-item">
        <span>${this.escapeHtml(label)}</span>
        <strong>${this.escapeHtml(value || "-")}</strong>
      </div>
    `;
  },

  renderMetricChart(points, key, palette, label) {
    if (!points || points.length === 0) {
      return `<div class="chart-empty">История ещё не накоплена для ${this.escapeHtml(label)}.</div>`;
    }

    const width = 900;
    const height = 260;
    const values = points.map((point) => Number(point[key] || 0));
    const max = Math.max(...values, 1);
    const stepX = width / Math.max(points.length - 1, 1);
    const linePoints = values.map((value, index) => {
      const x = index * stepX;
      const y = height - (value / max) * (height - 24) - 12;
      return `${x},${y}`;
    }).join(" ");
    const areaPoints = `0,${height} ${linePoints} ${width},${height}`;
    const latest = values[values.length - 1];
    const first = values[0];
    const delta = latest - first;
    const sign = delta >= 0 ? "+" : "";

    return `
      <div class="chart-wrap">
        <svg viewBox="0 0 ${width} ${height}" class="chart-svg" preserveAspectRatio="none" aria-label="${this.escapeHtml(label)}">
          <defs>
            <linearGradient id="gradient-${key}" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stop-color="${palette.fill.replace("rgba", "rgb").replace(/,[^)]+\)/, ")")}"></stop>
              <stop offset="100%" stop-color="rgba(11, 14, 24, 0.02)"></stop>
            </linearGradient>
          </defs>
          <polygon fill="${palette.fill}" points="${areaPoints}"></polygon>
          <polyline fill="none" stroke="${palette.stroke}" stroke-width="4" points="${linePoints}"></polyline>
        </svg>
        <div class="chart-legend">
          <strong>${this.escapeHtml(label)}</strong>
          <span>${this.formatNumber(latest, 2)} сейчас</span>
          <span>${sign}${this.formatNumber(delta, 2)} vs start</span>
        </div>
      </div>
    `;
  },

  async runAction(endpoint, successMessage) {
    const result = await this.api(endpoint, { method: "POST" });
    this.flash(result.message || successMessage, "success");
    if (this.activeRoute === "dashboard") {
      await this.renderDashboard(true);
    }
  },

  startPolling(fn, interval) {
    this.stopPolling();
    this.poller = window.setInterval(() => {
      if (document.visibilityState === "hidden") {
        return;
      }
      fn().catch((error) => this.flash(error.message || "Ошибка фонового обновления", "error"));
    }, interval);
  },

  stopPolling() {
    if (this.poller) {
      clearInterval(this.poller);
      this.poller = null;
    }
  },

  async api(url, options = {}) {
    const response = await fetch(url, {
      headers: {
        "Content-Type": "application/json",
      },
      ...options,
    });

    if (response.status === 401) {
      window.location.href = "/login";
      throw new Error("Session expired");
    }

    const text = await response.text();
    let payload = {};
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch {
        payload = { message: text };
      }
    }

    if (!response.ok) {
      throw new Error(payload.message || text || `HTTP ${response.status}`);
    }

    return payload;
  },

  flash(message, type = "success") {
    const stack = document.getElementById("flashStack");
    const node = document.createElement("div");
    node.className = `flash flash-${type}`;
    node.textContent = message;
    stack.appendChild(node);
    window.setTimeout(() => {
      node.remove();
    }, 4200);
  },

  linesToArray(value) {
    return value.split("\n").map((line) => line.trim()).filter(Boolean);
  },

  linesToTargets(value) {
    return this.linesToArray(value).map((line) => {
      const parts = line.split(/[\s|,]+/).filter(Boolean);
      return {
        value: parts[0] || "",
        weight: Number(parts[1] || 1),
      };
    }).filter((target) => target.value);
  },

  labelize(key) {
    return key.replaceAll("_", " ");
  },

  formatNumber(value, digits = 0) {
    return Number(value || 0).toLocaleString("ru-RU", {
      minimumFractionDigits: digits,
      maximumFractionDigits: digits,
    });
  },

  formatCompact(value) {
    return Number(value || 0).toLocaleString("ru-RU");
  },

  formatBytes(value) {
    const units = ["B", "KB", "MB", "GB", "TB"];
    let current = Number(value || 0);
    let unit = units[0];
    for (let i = 0; i < units.length && current >= 1024; i += 1) {
      unit = units[Math.min(i + 1, units.length - 1)];
      current /= 1024;
      if (current < 1024) {
        break;
      }
    }
    return `${this.formatNumber(current, current < 10 ? 1 : 0)} ${unit}`;
  },

  formatDuration(seconds) {
    const total = Math.floor(Number(seconds || 0));
    const days = Math.floor(total / 86400);
    const hours = Math.floor((total % 86400) / 3600);
    const minutes = Math.floor((total % 3600) / 60);
    if (days > 0) {
      return `${days}d ${hours}h`;
    }
    if (hours > 0) {
      return `${hours}h ${minutes}m`;
    }
    return `${minutes}m`;
  },

  escapeHtml(value) {
    return String(value ?? "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  },
};

window.addEventListener("DOMContentLoaded", () => app.init());
