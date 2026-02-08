const API_BASE = "http://127.0.0.1:8000";

/* ============================
   TOKEN HELPERS
============================ */
function setTokens(access, refresh) {
    localStorage.setItem("access_token", access);
    localStorage.setItem("refresh_token", refresh);
}

function clearTokens() {
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
}

function getAccessToken() {
    return localStorage.getItem("access_token");
}

function getRefreshToken() {
    return localStorage.getItem("refresh_token");
}

/* ============================
   AUTH API CALLS
============================ */
async function login(email, password) {
    const res = await fetch(`${API_BASE}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email, password }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Login failed");

    setTokens(data.access_token, data.refresh_token);
    return data;
}

async function register(name, email, password) {
    const res = await fetch(`${API_BASE}/register`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, password }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Registration failed");

    // auto-login after register
    return login(email, password);
}

/* ============================
   CURRENT USER
============================ */
async function userDetails() {
    const res = await fetch(`${API_BASE}/me`, {
        method: "POST",
        // headers: { "Content-Type": "application/json" },
        // body: JSON.stringify({ name, email, password }),
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.detail || "Registration failed");

    // auto-login after register
    return data;
}

async function getCurrentUser() {
    let token = getAccessToken();
    if (!token) return null;

    let res = await fetch(`${API_BASE}/me`, {
        headers: { Authorization: `Bearer ${token}` },
    });

    if (res.status === 401) {
        const refreshed = await refreshAccessToken();
        if (!refreshed) return null;

        token = getAccessToken();
        res = await fetch(`${API_BASE}/me`, {
            headers: { Authorization: `Bearer ${token}` },
        });
    }

    if (!res.ok) return null;
    return res.json();
}

/* ============================
   REFRESH FLOW
============================ */
async function refreshAccessToken() {
    const refresh = getRefreshToken();
    if (!refresh) return false;

    const res = await fetch(`${API_BASE}/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refresh }),
    });

    if (!res.ok) {
        clearTokens();
        return false;
    }

    const data = await res.json();
    localStorage.setItem("access_token", data.access_token);
    return true;
}

/* ============================
   LOGOUT
============================ */
function logout() {
    clearTokens();
    window.location.href = "auth.html";
}

/* ============================
   AUTH PAGE HANDLER
============================ */
document.addEventListener("DOMContentLoaded", () => {
    const form = document.querySelector("form");
    if (!form) return;

    form.addEventListener("submit", async () => {
        const isLogin = document.getElementById("tab-login").checked;

        const email = document.getElementById("email").value;
        const password = document.getElementById("password").value;

        try {
            if (isLogin) {
                await login(email, password);
            } else {
                const name = document.getElementById("name").value;
                const confirm = document.getElementById("confirm-password").value;

                if (password !== confirm) {
                    alert("Passwords do not match");
                    return;
                }

                await register(name, email, password);
            }

            window.location.href = "home.html";
        } catch (err) {
            alert(err.message);
        }
    });
});