/**
 * Helper function to get a cookie by name.
 * This is used to retrieve the CSRF token from its cookie.
 * @param {string} name The name of the cookie to retrieve.
 * @returns {string|null} The cookie value or null if not found.
 */
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

/**
 * Performs an authenticated fetch request, automatically adding the CSRF token header.
 * Handles token refresh on 401 Unauthorized responses.
 * @param {string} url The URL to fetch.
 * @param {RequestInit} options Fetch options (method, headers, body, etc.).
 * @returns {Promise<Response|null>} The fetch Response object or null if refresh fails.
 */
async function authenticatedFetch(url, options = {}) {
    const csrfToken = getCookie('X-CSRF-TOKEN'); // Read CSRF token from the cookie

    if (csrfToken) {
        options.headers = {
            ...options.headers,
            'X-CSRF-TOKEN': csrfToken, // Add CSRF token to a custom header
        };
    } else {
        console.warn('CSRF token not found in cookie. Request might fail.');
        // Depending on your security policy, you might want to throw an error or redirect to login.
    }

    const response = await fetch(url, options);

    // Handle token expiration/refresh if needed (e.g., 401 response)
    if (response.status === 401) {
        console.log('Authentication failed (401). Attempting to refresh token...');
        const refreshed = await refreshToken();
        if (refreshed) {
            console.log('Token refreshed, retrying original request.');
            // Retry the original request with the new tokens/cookies
            return authenticatedFetch(url, options);
        } else {
            console.error('Failed to refresh token. Redirecting to login.');
            // Redirect to login page
            window.location.href = '/login';
            return null; // Or throw an error
        }
    }

    return response;
}

/**
 * Handles user login. Sends credentials and expects HTTP-only JWTs and a CSRF cookie.
 * @param {string} username
 * @param {string} password
 * @returns {Promise<boolean>} True if login was successful, false otherwise.
 */
async function login(username, password) {
    try {
        const response = await fetch('/api/login', { // Replace with your actual login endpoint
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });

        if (response.ok) {
            const data = await response.json();
            console.log('Login successful!', data);
            // The HTTP-only access and refresh tokens are now set as cookies by the server.
            // The CSRF token is also set as a non-HTTP-only cookie (X-CSRF-TOKEN).
            // If your server also returns the CSRF token in the response body, you can use it here:
            // const csrfTokenFromBody = data.csrf_token;
            return true;
        } else {
            const errorData = await response.json();
            console.error('Login failed:', errorData.message);
            return false;
        }
    } catch (error) {
        console.error('Network error during login:', error);
        return false;
    }
}

/**
 * Attempts to refresh the access token using the refresh token cookie.
 * @returns {Promise<boolean>} True if token refresh was successful, false otherwise.
 */
async function refreshToken() {
    try {
        // The refresh token is automatically sent via the HTTP-only cookie by the browser.
        const response = await fetch('/api/refresh', { // Replace with your actual refresh endpoint
            method: 'POST',
            // No body needed if refresh token is in cookie
        });

        if (response.ok) {
            const data = await response.json();
            console.log('Token refresh successful!', data);
            // New access, refresh, and CSRF cookies are set by the server.
            // The new CSRF token is also returned in the response body if your server does so.
            return true;
        } else {
            console.error('Token refresh failed.');
            return false;
        }
    } catch (error) {
        console.error('Network error during token refresh:', error);
        return false;
    }
}

/**
 * Handles user logout. Sends a request to clear tokens and cookies.
 * @returns {Promise<boolean>} True if logout was successful, false otherwise.
 */
async function logout() {
    try {
        // The access token is automatically sent via the HTTP-only cookie.
        // The CSRF token is also sent via the header for this POST request.
        const response = await authenticatedFetch('/api/logout', { // Replace with your actual logout endpoint
            method: 'POST',
        });

        if (response.ok) {
            console.log('Logout successful!');
            // Server clears cookies. Client might also clear any local state.
            window.location.href = '/login'; // Redirect to login page
            return true;
        } else {
            console.error('Logout failed.');
            return false;
        }
    } catch (error) {
        console.error('Network error during logout:', error);
        return false;
    }
}

// --- Example Usage ---
// Assuming you have HTML elements for login/logout/data fetching

// Example: Call login on a button click
// document.getElementById('loginButton').addEventListener('click', async () => {
//     const username = document.getElementById('usernameInput').value;
//     const password = document.getElementById('passwordInput').value;
//     await login(username, password);
// });

// Example: Fetch protected data after login
// document.getElementById('fetchDataButton').addEventListener('click', async () => {
//     const response = await authenticatedFetch('/api/protected-data'); // Replace with your protected endpoint
//     if (response && response.ok) {
//         const data = await response.json();
//         console.log('Protected data:', data);
//     } else if (response) {
//         console.error('Failed to fetch protected data:', response.status, response.statusText);
//     }
// });

// Example: Call logout on a button click
// document.getElementById('logoutButton').addEventListener('click', async () => {
//     await logout();
// });

// Initial check (e.g., on page load)
// if (getCookie('access_token')) { // Check for the presence of the access token cookie (though HTTP-only, this check is for conceptual understanding if you had a non-HTTP-only flag for some reason, or if you're checking for the CSRF cookie instead)
//     console.log('User might be authenticated. CSRF token cookie:', getCookie('X-CSRF-TOKEN'));
// } else {
//     console.log('User not authenticated.');
// }

/*
Erläuterung der Client-seitigen Logik:

getCookie(name): Eine Hilfsfunktion, um den Wert eines Cookies anhand seines Namens zu lesen. Diese ist notwendig, um den CSRF-Token aus dem Cookie zu extrahieren, da er im X-CSRF-TOKEN-Cookie gespeichert wird.
authenticatedFetch(url, options):
Dies ist eine Wrapper-Funktion um die native fetch-API.
Sie liest den CSRF-Token aus dem X-CSRF-TOKEN-Cookie.
Fügt den gelesenen CSRF-Token als X-CSRF-TOKEN-Header zu jeder Anfrage hinzu. Ihr Backend muss diesen Header dann validieren.
Behandelt 401 (Unauthorized) Antworten, indem versucht wird, den Token über die refreshToken()-Funktion zu erneuern. Bei Erfolg wird die ursprüngliche Anfrage wiederholt.
login(username, password): Sendet Anmeldeinformationen an Ihr Backend. Das Backend sollte daraufhin die HTTP-only JWTs und den nicht-HTTP-only CSRF-Cookie setzen.
refreshToken(): Sendet eine Anfrage an Ihr Backend, um die Tokens zu erneuern. Der Browser sendet den HTTP-only Refresh-Token-Cookie automatisch mit. Das Backend sollte dann neue HTTP-only JWTs und einen neuen CSRF-Cookie setzen.
logout(): Sendet eine Anfrage zum Abmelden. Das Backend sollte die Tokens auf die Blacklist setzen und die Cookies löschen.
Wichtige Sicherheitshinweise für die Client-Seite:

HTTP-only Cookies: Da die Access- und Refresh-Tokens als HTTP-only Cookies gesetzt werden, kann JavaScript nicht direkt auf sie zugreifen. Dies mindert das Risiko von Cross-Site Scripting (XSS)-Angriffen, bei denen ein Angreifer versuchen könnte, Ihre Tokens zu stehlen.
CSRF (Double-Submit Cookie Pattern): Der CSRF-Token wird sowohl im Cookie als auch im Request-Header gesendet. Das Backend vergleicht diese beiden Werte. Da ein Angreifer von einer anderen Domain aus nicht den Wert des Cookies lesen kann (Same-Origin Policy) und somit den korrekten Header nicht fälschen kann, wird der Angriff verhindert.
HTTPS: Stellen Sie in der Produktion unbedingt sicher, dass Ihre Website über HTTPS läuft und die cookieSecure-Option in Ihrer PHP-Konfiguration auf true gesetzt ist.
SameSite-Cookies: Die SameSite=Lax-Einstellung bietet einen guten Schutz gegen viele CSRF-Angriffe, ohne die Benutzerfreundlichkeit stark einzuschränken.
*/