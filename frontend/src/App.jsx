
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Bell,
  CheckCircle2,
  Clock3,
  LayoutDashboard,
  Menu,
  Network,
  Plus,
  RefreshCw,
  Search,
  Shield,
  ShieldCheck,
  X,
} from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
  PieChart,
  Pie,
  Cell,
} from "recharts";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000/api";

const RISK_COLORS = {
  INFO: "#64748b",
  LOW: "#22c55e",
  MEDIUM: "#f59e0b",
  HIGH: "#ef4444",
};

function getField(record, ...keys) {
  for (const key of keys) {
    if (record?.[key] !== undefined && record?.[key] !== null) {
      return record[key];
    }
  }
  return "";
}

function normalizeAlerts(data) {
  if (Array.isArray(data)) return data;
  if (Array.isArray(data?.alerts)) return data.alerts;
  if (Array.isArray(data?.items)) return data.items;
  if (Array.isArray(data?.results)) return data.results;
  return [];
}

function formatDate(value) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value);
  return date.toLocaleString();
}

function StatCard({ title, value, caption, icon: Icon, tone }) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${tone}`}>
        <Icon size={20} />
      </div>
      <div className="stat-content">
        <span className="stat-title">{title}</span>
        <strong>{value}</strong>
        <span className="stat-caption">{caption}</span>
      </div>
    </div>
  );
}

function RiskBadge({ level }) {
  const normalized = String(level || "INFO").toUpperCase();
  return (
    <span className={`risk-badge risk-${normalized.toLowerCase()}`}>
      <span className="badge-dot" />
      {normalized}
    </span>
  );
}

function StatusBadge({ status }) {
  const normalized = String(status || "NEW").toUpperCase();
  return (
    <span className={`status-badge status-${normalized.toLowerCase()}`}>
      {normalized.replace("_", " ")}
    </span>
  );
}

function App() {
  const [alerts, setAlerts] = useState([]);
  const [statistics, setStatistics] = useState({});
  const [activePage, setActivePage] = useState("Overview");
  const [search, setSearch] = useState("");
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState("");
  const [lastUpdated, setLastUpdated] = useState(null);
  const [updatingId, setUpdatingId] = useState(null);
  const [showIncidentForm, setShowIncidentForm] = useState(false);
  const [incidentTitle, setIncidentTitle] = useState("");
  const [incidentDescription, setIncidentDescription] = useState("");
  const [incidentSeverity, setIncidentSeverity] = useState("MEDIUM");
  const [selectedIncidentAlert, setSelectedIncidentAlert] = useState("");
  const [notice, setNotice] = useState("");

  const fetchDashboard = useCallback(async () => {
    setLoading(true);
    setApiError("");

    try {
      const [alertsResponse, statsResponse] = await Promise.all([
        fetch(`${API_BASE}/alerts?limit=500`),
        fetch(`${API_BASE}/statistics`),
      ]);

      if (!alertsResponse.ok) {
        throw new Error(`Alerts API returned ${alertsResponse.status}`);
      }
      if (!statsResponse.ok) {
        throw new Error(`Statistics API returned ${statsResponse.status}`);
      }

      const alertsData = await alertsResponse.json();
      const statsData = await statsResponse.json();

      setAlerts(normalizeAlerts(alertsData));
      setStatistics(statsData || {});
      setLastUpdated(new Date());
    } catch (error) {
      setApiError(
        `${error.message}. Check that FastAPI is running at 127.0.0.1:8000.`
      );
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboard();
  }, [fetchDashboard]);

  const filteredAlerts = useMemo(() => {
    return alerts.filter((alert) => {
      const id = String(getField(alert, "alert_id", "id"));
      const source = String(getField(alert, "source_ip", "src_ip"));
      const destination = String(
        getField(alert, "destination_ip", "dst_ip")
      );
      const description = String(
        getField(alert, "description", "rule_name", "alert_type")
      );
      const risk = String(getField(alert, "risk_level") || "INFO").toUpperCase();
      const status = String(getField(alert, "status") || "NEW").toUpperCase();

      const matchesSearch = [id, source, destination, description]
        .join(" ")
        .toLowerCase()
        .includes(search.toLowerCase());

      const matchesRisk = riskFilter === "ALL" || risk === riskFilter;
      const matchesStatus =
        statusFilter === "ALL" || status === statusFilter;

      return matchesSearch && matchesRisk && matchesStatus;
    });
  }, [alerts, search, riskFilter, statusFilter]);

  const riskCounts = useMemo(() => {
    const counts = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    alerts.forEach((alert) => {
      const risk = String(getField(alert, "risk_level") || "INFO").toUpperCase();
      if (counts[risk] !== undefined) counts[risk] += 1;
    });
    return counts;
  }, [alerts]);

  const statusCounts = useMemo(() => {
    const counts = {
      NEW: 0,
      INVESTIGATING: 0,
      RESOLVED: 0,
      FALSE_POSITIVE: 0,
    };
    alerts.forEach((alert) => {
      const status = String(getField(alert, "status") || "NEW").toUpperCase();
      if (counts[status] !== undefined) counts[status] += 1;
    });
    return counts;
  }, [alerts]);

  const highRiskCount =
    Number(
      getField(statistics, "high_risk_alerts", "high_risk", "high_alerts")
    ) || riskCounts.HIGH;

  const totalCount =
    Number(getField(statistics, "total_alerts", "total")) || alerts.length;

  const newCount = statusCounts.NEW;
  const investigatingCount = statusCounts.INVESTIGATING;

  const riskChartData = [
    { name: "High", value: riskCounts.HIGH, color: RISK_COLORS.HIGH },
    { name: "Medium", value: riskCounts.MEDIUM, color: RISK_COLORS.MEDIUM },
    { name: "Low", value: riskCounts.LOW, color: RISK_COLORS.LOW },
    { name: "Info", value: riskCounts.INFO, color: RISK_COLORS.INFO },
  ];

  const trendData = useMemo(() => {
    const buckets = new Map();

    alerts.forEach((alert) => {
      const rawDate = getField(alert, "created_at", "timestamp", "alert_time");
      const date = rawDate ? new Date(rawDate) : null;
      if (!date || Number.isNaN(date.getTime())) return;

      const key = date.toLocaleDateString([], {
        month: "short",
        day: "numeric",
      });
      buckets.set(key, (buckets.get(key) || 0) + 1);
    });

    return Array.from(buckets.entries())
      .map(([day, count]) => ({ day, count }))
      .slice(-7);
  }, [alerts]);

  async function updateAlert(alertId, newStatus) {
    setUpdatingId(alertId);
    setNotice("");

    try {
      const response = await fetch(
        `${API_BASE}/alerts/${alertId}/status`,
        {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            status: newStatus,
            analyst_notes: "Status updated from the Network IDS dashboard.",
          }),
        }
      );

      if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.detail || `Request failed: ${response.status}`);
      }

      setNotice(`Alert #${alertId} updated to ${newStatus}.`);
      await fetchDashboard();
    } catch (error) {
      setNotice(`Update failed: ${error.message}`);
    } finally {
      setUpdatingId(null);
    }
  }

  async function createIncident(event) {
    event.preventDefault();
    setNotice("");

    try {
      const response = await fetch(`${API_BASE}/incidents`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          incident_title: incidentTitle,
          description: incidentDescription,
          severity: incidentSeverity,
        }),
      });

      const result = await response.json();
      if (!response.ok) {
        throw new Error(result.detail || "Incident creation failed");
      }

      if (selectedIncidentAlert) {
        const linkResponse = await fetch(
          `${API_BASE}/incidents/${result.incident_id}/alerts/${selectedIncidentAlert}`,
          { method: "POST" }
        );

        if (!linkResponse.ok) {
          throw new Error(
            "Incident created, but linking the selected alert failed."
          );
        }
      }

      setNotice(`Incident #${result.incident_id} created successfully.`);
      setIncidentTitle("");
      setIncidentDescription("");
      setIncidentSeverity("MEDIUM");
      setSelectedIncidentAlert("");
      setShowIncidentForm(false);
    } catch (error) {
      setNotice(error.message);
    }
  }

  const navigation = [
    { name: "Overview", icon: LayoutDashboard },
    { name: "Alerts", icon: Bell },
    { name: "Incidents", icon: ShieldCheck },
  ];

  const recentAlerts = [...alerts]
    .sort((a, b) => {
      const aDate = new Date(getField(a, "created_at", "timestamp") || 0);
      const bDate = new Date(getField(b, "created_at", "timestamp") || 0);
      return bDate - aDate;
    })
    .slice(0, 6);

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><Shield size={23} /></div>
          <div>
            <strong>NetSentinel</strong>
            <span>NETWORK IDS</span>
          </div>
        </div>

        <div className="sidebar-label">WORKSPACE</div>
        <nav className="navigation">
          {navigation.map(({ name, icon: Icon }) => (
            <button
              key={name}
              className={`nav-item ${activePage === name ? "active" : ""}`}
              onClick={() => setActivePage(name)}
            >
              <Icon size={18} />
              <span>{name}</span>
              {name === "Alerts" && <span className="nav-count">{newCount}</span>}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="system-status">
            <span className="live-dot" />
            <div>
              <strong>Monitoring system</strong>
              <span>Local simulation</span>
            </div>
          </div>
          <div className="sidebar-footer">DEFENSIVE IDS SIMULATION</div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div className="mobile-brand">
            <Shield size={21} /> NetSentinel
          </div>
          <div className="breadcrumb">
            Security Operations <span>/</span> {activePage}
          </div>
          <div className="topbar-actions">
            <span className="environment-tag">SIMULATION ENVIRONMENT</span>
            <button
              className="icon-button"
              title="Refresh dashboard"
              onClick={fetchDashboard}
              disabled={loading}
            >
              <RefreshCw size={17} className={loading ? "spin" : ""} />
            </button>
            <div className="avatar">AK</div>
          </div>
        </header>

        <div className="page-container">
          <div className="page-heading">
            <div>
              <div className="eyebrow">SECURITY MONITORING CENTER</div>
              <h1>{activePage}</h1>
              <p>
                Monitor synthetic network activity and investigate detection
                alerts.
              </p>
            </div>
            <div className="heading-actions">
              <span className="last-updated">
                {lastUpdated
                  ? `Updated ${lastUpdated.toLocaleTimeString()}`
                  : "Waiting for data"}
              </span>
              <button className="primary-button" onClick={() => setShowIncidentForm(true)}>
                <Plus size={17} /> New incident
              </button>
            </div>
          </div>

          {apiError && (
            <div className="error-banner">
              <AlertTriangle size={18} />
              <span>{apiError}</span>
              <button onClick={fetchDashboard}>Retry</button>
            </div>
          )}

          {notice && (
            <div className="notice-banner">
              <span>{notice}</span>
              <button onClick={() => setNotice("")}><X size={16} /></button>
            </div>
          )}

          {activePage === "Overview" && (
            <>
              <section className="stats-grid">
                <StatCard
                  title="Total alerts"
                  value={totalCount.toLocaleString()}
                  caption="Recorded detection alerts"
                  icon={Activity}
                  tone="blue"
                />
                <StatCard
                  title="High-risk alerts"
                  value={highRiskCount.toLocaleString()}
                  caption="Requires analyst attention"
                  icon={AlertTriangle}
                  tone="red"
                />
                <StatCard
                  title="New alerts"
                  value={newCount.toLocaleString()}
                  caption="Awaiting investigation"
                  icon={Bell}
                  tone="amber"
                />
                <StatCard
                  title="Investigating"
                  value={investigatingCount.toLocaleString()}
                  caption="Currently under review"
                  icon={Clock3}
                  tone="purple"
                />
              </section>

              <section className="charts-grid">
                <div className="panel trend-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Alert activity</h2>
                      <p>Alert records grouped by date</p>
                    </div>
                    <span className="panel-tag">RECORDED DATA</span>
                  </div>
                  {trendData.length ? (
                    <ResponsiveContainer width="100%" height={235}>
                      <AreaChart data={trendData}>
                        <defs>
                          <linearGradient id="alertGradient" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor="#38bdf8" stopOpacity={0.3} />
                            <stop offset="100%" stopColor="#38bdf8" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid stroke="#263449" strokeDasharray="3 3" vertical={false} />
                        <XAxis dataKey="day" stroke="#8290a5" tickLine={false} axisLine={false} />
                        <YAxis stroke="#8290a5" tickLine={false} axisLine={false} allowDecimals={false} />
                        <Tooltip
                          contentStyle={{
                            background: "#111d2e",
                            border: "1px solid #30415a",
                            borderRadius: 10,
                          }}
                        />
                        <Area
                          type="monotone"
                          dataKey="count"
                          stroke="#38bdf8"
                          strokeWidth={2}
                          fill="url(#alertGradient)"
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="empty-chart">No timestamp data available yet.</div>
                  )}
                </div>

                <div className="panel risk-panel">
                  <div className="panel-heading">
                    <div>
                      <h2>Risk distribution</h2>
                      <p>Alerts grouped by risk level</p>
                    </div>
                  </div>
                  <div className="donut-wrap">
                    <ResponsiveContainer width="100%" height={190}>
                      <PieChart>
                        <Pie
                          data={riskChartData}
                          dataKey="value"
                          nameKey="name"
                          innerRadius={57}
                          outerRadius={80}
                          paddingAngle={3}
                          stroke="none"
                        >
                          {riskChartData.map((entry) => (
                            <Cell key={entry.name} fill={entry.color} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            background: "#111d2e",
                            border: "1px solid #30415a",
                            borderRadius: 10,
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    <div className="donut-center">
                      <strong>{alerts.length}</strong>
                      <span>ALERTS</span>
                    </div>
                  </div>
                  <div className="risk-legend">
                    {riskChartData.map((item) => (
                      <div key={item.name}>
                        <span><i style={{ background: item.color }} />{item.name}</span>
                        <strong>{item.value}</strong>
                      </div>
                    ))}
                  </div>
                </div>
              </section>

              <section className="panel table-panel">
                <div className="panel-heading">
                  <div>
                    <h2>Recent alerts</h2>
                    <p>Latest records from the detection engine</p>
                  </div>
                  <button className="text-button" onClick={() => setActivePage("Alerts")}>
                    View all alerts →
                  </button>
                </div>
                <AlertTable
                  alerts={recentAlerts}
                  updatingId={updatingId}
                  onUpdate={updateAlert}
                  compact
                />
              </section>
            </>
          )}

          {activePage === "Alerts" && (
            <section className="panel table-panel">
              <div className="panel-heading alerts-heading">
                <div>
                  <h2>Detection alerts</h2>
                  <p>Search, filter, and update alert investigation status</p>
                </div>
                <span className="record-count">{filteredAlerts.length} records</span>
              </div>
              <div className="filter-toolbar">
                <div className="search-box">
                  <Search size={17} />
                  <input
                    value={search}
                    onChange={(event) => setSearch(event.target.value)}
                    placeholder="Search IP, alert ID, or description..."
                  />
                </div>
                <select value={riskFilter} onChange={(event) => setRiskFilter(event.target.value)}>
                  <option value="ALL">All risk levels</option>
                  <option value="HIGH">High</option>
                  <option value="MEDIUM">Medium</option>
                  <option value="LOW">Low</option>
                  <option value="INFO">Info</option>
                </select>
                <select value={statusFilter} onChange={(event) => setStatusFilter(event.target.value)}>
                  <option value="ALL">All statuses</option>
                  <option value="NEW">New</option>
                  <option value="INVESTIGATING">Investigating</option>
                  <option value="RESOLVED">Resolved</option>
                  <option value="FALSE_POSITIVE">False positive</option>
                </select>
              </div>
              <AlertTable
                alerts={filteredAlerts}
                updatingId={updatingId}
                onUpdate={updateAlert}
              />
            </section>
          )}

          {activePage === "Incidents" && (
            <section className="panel incident-panel">
              <div className="panel-heading">
                <div>
                  <h2>Incident management</h2>
                  <p>Create incidents and associate detection alerts.</p>
                </div>
                <button className="primary-button" onClick={() => setShowIncidentForm(true)}>
                  <Plus size={17} /> Create incident
                </button>
              </div>
              <div className="incident-intro">
                <div className="incident-icon"><ShieldCheck size={28} /></div>
                <div>
                  <strong>Investigation workspace</strong>
                  <p>
                    Use the incident form to record an investigation and
                    optionally link an existing alert.
                  </p>
                </div>
              </div>
              <div className="incident-note">
                <AlertTriangle size={17} />
                The current API supports incident creation and alert linking.
                An incident listing endpoint is not yet implemented.
              </div>
            </section>
          )}

          <footer className="page-footer">
            <span><Network size={14} /> Network IDS Simulation</span>
            <span><span className="live-dot" /> Local defensive monitoring</span>
          </footer>
        </div>
      </main>

      {showIncidentForm && (
        <div className="modal-backdrop" onClick={() => setShowIncidentForm(false)}>
          <form className="incident-modal" onClick={(event) => event.stopPropagation()} onSubmit={createIncident}>
            <div className="modal-heading">
              <div>
                <span className="eyebrow">CASE MANAGEMENT</span>
                <h2>Create incident</h2>
              </div>
              <button type="button" className="icon-button" onClick={() => setShowIncidentForm(false)}>
                <X size={19} />
              </button>
            </div>

            <label>
              Incident title
              <input
                required
                minLength={3}
                maxLength={200}
                value={incidentTitle}
                onChange={(event) => setIncidentTitle(event.target.value)}
                placeholder="e.g. Suspicious connection activity"
              />
            </label>

            <label>
              Description
              <textarea
                maxLength={2000}
                value={incidentDescription}
                onChange={(event) => setIncidentDescription(event.target.value)}
                placeholder="Describe the investigation..."
                rows={4}
              />
            </label>

            <label>
              Severity
              <select value={incidentSeverity} onChange={(event) => setIncidentSeverity(event.target.value)}>
                <option value="LOW">Low</option>
                <option value="MEDIUM">Medium</option>
                <option value="HIGH">High</option>
                <option value="CRITICAL">Critical</option>
              </select>
            </label>

            <label>
              Link an alert (optional)
              <select value={selectedIncidentAlert} onChange={(event) => setSelectedIncidentAlert(event.target.value)}>
                <option value="">Do not link an alert</option>
                {alerts.map((alert) => {
                  const id = getField(alert, "alert_id", "id");
                  return (
                    <option key={id} value={id}>
                      Alert #{id} — {getField(alert, "risk_level") || "INFO"}
                    </option>
                  );
                })}
              </select>
            </label>

            <div className="modal-actions">
              <button type="button" className="secondary-button" onClick={() => setShowIncidentForm(false)}>
                Cancel
              </button>
              <button type="submit" className="primary-button">
                <Plus size={16} /> Create incident
              </button>
            </div>
          </form>
        </div>
      )}

      {loading && alerts.length === 0 && !apiError && (
        <div className="loading-overlay">
          <RefreshCw className="spin" size={24} />
          <span>Connecting to detection API...</span>
        </div>
      )}
    </div>
  );
}

function AlertTable({ alerts, updatingId, onUpdate, compact = false }) {
  if (!alerts.length) {
    return (
      <div className="empty-table">
        <Shield size={25} />
        <strong>No alerts to display</strong>
        <span>Try changing your filters or check the backend dataset.</span>
      </div>
    );
  }

  return (
    <div className="table-scroll">
      <table className="alerts-table">
        <thead>
          <tr>
            <th>ALERT</th>
            <th>SOURCE</th>
            <th>DESTINATION</th>
            <th>RISK</th>
            <th>STATUS</th>
            {!compact && <th>DETECTED</th>}
            <th>ACTION</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((alert, index) => {
            const id = getField(alert, "alert_id", "id") || index + 1;
            const source = getField(alert, "source_ip", "src_ip") || "—";
            const destination =
              getField(alert, "destination_ip", "dst_ip") || "—";
            const risk = getField(alert, "risk_level") || "INFO";
            const status = getField(alert, "status") || "NEW";
            const description =
              getField(alert, "description", "rule_name", "alert_type") ||
              getField(alert, "scenario_type") ||
              "Network activity detected";
            const detected = getField(alert, "created_at", "timestamp");

            return (
              <tr key={id}>
                <td>
                  <div className="alert-cell">
                    <strong>#{id}</strong>
                    <span title={description}>{String(description).slice(0, 42)}</span>
                  </div>
                </td>
                <td className="ip-cell">{source}</td>
                <td className="ip-cell">{destination}</td>
                <td><RiskBadge level={risk} /></td>
                <td><StatusBadge status={status} /></td>
                {!compact && <td className="date-cell">{formatDate(detected)}</td>}
                <td>
                  <select
                    className="status-select"
                    value={status}
                    disabled={updatingId === id}
                    onChange={(event) => onUpdate(id, event.target.value)}
                    aria-label={`Update status for alert ${id}`}
                  >
                    <option value="NEW">New</option>
                    <option value="INVESTIGATING">Investigating</option>
                    <option value="RESOLVED">Resolved</option>
                    <option value="FALSE_POSITIVE">False positive</option>
                  </select>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default App;