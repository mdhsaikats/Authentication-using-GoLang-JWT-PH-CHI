const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const baseURL = window.location.origin; // Use same origin as the page

// --- Firebase Configuration ---
// TODO: Replace with your actual config from Firebase Console
const firebaseConfig = {
  apiKey: "AIzaSyCdNpLEgj2qq_kftN-ZV_g4tW8ryP5WlB0",
  authDomain: "authentication-ccfb6.firebaseapp.com",
  projectId: "authentication-ccfb6",
  storageBucket: "authentication-ccfb6.firebasestorage.app",
  messagingSenderId: "268785185138",
  appId: "1:268785185138:web:b764dec57d80bcd7f0adeb",
  measurementId: "G-2ZF1WLYFJN"
};

// Initialize Firebase
if (typeof firebase !== 'undefined') {
  firebase.initializeApp(firebaseConfig);
  
  // Observer for Auth State Changes
  firebase.auth().onAuthStateChanged((user) => {
    if (user) {
      console.log('User is signed in:', user);
      // You could update UI here, e.g., show user profile pic
    } else {
      console.log('User is signed out');
      // If on a protected page, you might redirect:
      // if (window.location.pathname.includes('dashboard.html')) window.location.href = 'index.html';
    }
  });

} else {
  // Graceful fallback if SDK fails to load or offline
  console.warn("Firebase SDK not loaded");
}
// -----------------------------

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
    return null;
}

function csrfHeaders() {
    const token = getCookie('csrf_token');
    return token ? { 'X-CSRF-Token': token } : {};
}

// Toggle password visibility
const togglePassword = document.getElementById('togglePassword');
if (togglePassword) {
    togglePassword.addEventListener('click', () => {
        const passwordInput = document.getElementById('password');
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            togglePassword.src = '../asset/hidden.png';
        } else {
            passwordInput.type = 'password';
            togglePassword.src = '../asset/eye.png';
        }
    });
}

// Toggle confirm password visibility
const toggleConfirmPassword = document.getElementById('toggleConfirmPassword');
if (toggleConfirmPassword) {
    toggleConfirmPassword.addEventListener('click', () => {
        const confirmPasswordInput = document.getElementById('confirm_password');
        if (confirmPasswordInput.type === 'password') {
            confirmPasswordInput.type = 'text';
            toggleConfirmPassword.src = '../asset/hidden.png';
        } else {
            confirmPasswordInput.type = 'password';
            toggleConfirmPassword.src = '../asset/eye.png';
        }
    });
}

function showNotification(message, type = 'error') {
    const notification = document.createElement('div');
    notification.className = `fixed top-4 right-4 px-6 py-4 rounded-lg shadow-lg text-white z-50 transition-all duration-300 ${
        type === 'success' ? 'bg-green-500' : 
        type === 'error' ? 'bg-red-500' : 
        type === 'info' ? 'bg-blue-500' : 'bg-yellow-500'
    }`;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

if (loginForm) {
    loginForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(loginForm);
        const data = {
            username: formData.get('username'),
            password_hash: formData.get('password')  
        };
        
        try {
            const response = await fetch(`${baseURL}/auth`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...csrfHeaders()
                },
                body: JSON.stringify(data),
                credentials: 'include'
            });
            
            
            const contentType = response.headers.get('content-type');
            let result;
            
            if (contentType && contentType.includes('application/json')) {
                result = await response.json();
                if (response.ok) {
                    showNotification('Login successful! Redirecting...', 'success');
                    setTimeout(() => {
                        window.location.href = 'user_dashboard.html';
                    }, 1000);
                } else {
                    showNotification(result.message || 'Login failed', 'error');
                }
            } else {
                result = await response.text();
                if (response.ok) {
                    showNotification('Login successful! Redirecting...', 'success');
                    setTimeout(() => {
                        window.location.href = 'user_dashboard.html';
                    }, 1000);
                } else {
                    showNotification(result, 'error');
                }
            }
        } catch (error) {
            showNotification('Login failed: ' + error.message, 'error');
        }
    });
}


if (registerForm) {
    registerForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        // Validate password strength
        if (!validatePassword()) {
            return;
        }
        
        // Check if passwords match
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm_password').value;
        if (password !== confirmPassword) {
            showNotification('Passwords do not match', 'error');
            return;
        }
        
        const formData = new FormData(registerForm);
        const data = {
            name: formData.get('name'),
            username: formData.get('username'),
            password_hash: formData.get('password')  
        };
        
        try {
            const response = await fetch(`${baseURL}/auth/register`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...csrfHeaders()
                },
                body: JSON.stringify(data),
                credentials: 'include'
            });
            
            
            const contentType = response.headers.get('content-type');
            let result;
            
            if (contentType && contentType.includes('application/json')) {
                result = await response.json();
                if (response.ok) {
                    showNotification(result.success || 'Registration successful! Redirecting to login...', 'success');
                    setTimeout(() => {
                        window.location.href = 'index.html';
                    }, 1500);
                } else {
                    showNotification(result.message || 'Registration failed', 'error');
                }
            } else {
                result = await response.text();
                if (response.ok) {
                    showNotification('Registration successful! Redirecting to login...', 'success');
                    setTimeout(() => {
                        window.location.href = 'index.html';
                    }, 1500);
                } else {
                    showNotification(result, 'error');
                }
            }
        } catch (error) {
            showNotification('Registration failed: ' + error.message, 'error');
        }
    });
}


window.onload = async () => {
    const currentPage = window.location.pathname;
    
    // Only check auth on login/register pages, not on dashboard
    if (!currentPage.includes('index.html') && !currentPage.includes('register.html')) {
        return;
    }
    
    try {
        const response = await fetch(`${baseURL}/dashboard`, {
            method: 'GET',
            credentials: 'include'
        });
        if (response.status === 200) {
            // Already authenticated, redirect to dashboard
            window.location.href = 'dashboard.html';
        }
    } catch (error) {
        console.error('Error checking login status:', error);
    }
}

function isStrongPassword(password) {
    const strongRegex = /^(?=.*[a-zA-Z])(?=.*\d).{8,}$/;
    return strongRegex.test(password);
}

function validatePassword() {
    const password = document.getElementById('password').value;
    
    if (!isStrongPassword(password)) {
        showNotification('Password must be at least 8 characters with a letter and a number', 'error');
        return false;
    }
    
    return true;
}

// --- Google Sign-In Logic ---
const googleLoginBtn = document.getElementById('googleLoginBtn');

if (googleLoginBtn) {
    googleLoginBtn.addEventListener('click', async () => {
        if (typeof firebase === 'undefined') {
             showNotification("Firebase not initialized. Check console.", 'error');
             return;
        }

        const provider = new firebase.auth.GoogleAuthProvider();
        
        try {
            const result = await firebase.auth().signInWithPopup(provider);
            const user = result.user;
            
            console.log("Google User:", user);
            const token = await user.getIdToken();
            console.log("ID Token:", token);

            // Send 'token' to your Go backend for verification!
            const verifyResponse = await fetch(`${baseURL}/auth/google`, {
                 method: 'POST',
                 headers: {
                     'Content-Type': 'application/json',
                     ...csrfHeaders()
                 },
                 body: JSON.stringify({ token: token }),
                 credentials: 'include'
            });

            if (!verifyResponse.ok) {
                const errMsg = await verifyResponse.text();
                throw new Error("Backend verification failed: " + errMsg);
            }

            showNotification(`Login successful as ${user.displayName}!`, 'success');
            
            // Redirect after short delay
            setTimeout(() => {
                window.location.href = 'user_dashboard.html'; 
            }, 1000);

        } catch (error) {
            console.error("Google Sign-in Error:", error);
            showNotification(error.message, 'error');
        }
    });
}

// --- Logout Logic ---
const logoutBtn = document.getElementById('logoutBtn');
if (logoutBtn) {
    logoutBtn.addEventListener('click', async () => {
        try {
            // 1. Sign out from Firebase
            if (typeof firebase !== 'undefined') {
                await firebase.auth().signOut();
                console.log("Signed out from Firebase");
            }

            // 2. Sign out from Backend (if applicable)
             await fetch(`${baseURL}/auth/logout`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...csrfHeaders()
                },
                body: JSON.stringify({}),
                credentials: 'include'
            });

            showNotification('Logged out successfully', 'success');
            setTimeout(() => {
                window.location.href = 'index.html';
            }, 500);

        } catch (error) {
            console.error("Logout error:", error);
            // Force redirect anyway
            window.location.href = 'index.html';
        }
    });
}