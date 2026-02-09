const loginForm = document.getElementById('loginForm');
const registerForm = document.getElementById('registerForm');
const baseURL = 'http://localhost:8080';

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
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
            });
            
            
            const contentType = response.headers.get('content-type');
            let result;
            
            if (contentType && contentType.includes('application/json')) {
                result = await response.json();
                if (response.ok) {
                
                    localStorage.setItem('authToken', result.token);
                    showNotification('Login successful! Redirecting...', 'success');
                    setTimeout(() => {
                        window.location.href = 'home.html';
                    }, 1000);
                } else {
                    showNotification(result.message || 'Login failed', 'error');
                }
            } else {
                result = await response.text();
                if (response.ok) {
                    // Assume the text response is the token itself
                    localStorage.setItem('authToken', result);
                    showNotification('Login successful! Redirecting...', 'success');
                    setTimeout(() => {
                        window.location.href = 'home.html';
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
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(data)
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
    const token = localStorage.getItem('authToken');
    if (!token) {
        return; 
    }
    
    try {
        const response = await fetch(`${baseURL}/dashboard`, {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        if (response.status === 200) {
            
            const currentPage = window.location.pathname;
            if (currentPage.includes('index.html') || currentPage.includes('register.html')) {
                window.location.href = 'home.html';
            }
        } else if (response.status === 401) {
           
            localStorage.removeItem('authToken');
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