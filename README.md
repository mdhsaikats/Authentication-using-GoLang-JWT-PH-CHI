# 🔐 Auth - Modern JWT Authentication System

> A sleek, secure, and production-ready authentication system that combines the power of Go with the simplicity of vanilla JavaScript.

[![Go Version](https://img.shields.io/badge/Go-1.25.3-00ADD8?style=flat&logo=go)](https://go.dev/)
[![MySQL](https://img.shields.io/badge/MySQL-8.0-4479A1?style=flat&logo=mysql&logoColor=white)](https://www.mysql.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## 🎯 What is This?

Ever wondered how login systems actually work? This project is a complete, from-scratch implementation of a JWT-based authentication system. No bloated frameworks, no unnecessary complexity—just clean, readable code that demonstrates modern authentication practices.

Perfect for learning, prototyping, or as a foundation for your next project!

## ✨ Features That Matter

- 🛡️ **Military-Grade Security** - Bcrypt hashing with cost factor 14 (that's 2^14 iterations!)
- 🎫 **JWT Authentication** - Stateless, scalable token-based auth
- 🚀 **Lightning Fast** - Go's concurrency makes it blazingly fast
- 🎨 **Beautiful UI** - Clean, responsive design with Tailwind CSS
- 🔔 **Smart Notifications** - Real-time toast messages for user actions
- 🔄 **Auto-Redirect** - Smart routing based on authentication state
- 📱 **Mobile Ready** - Fully responsive across all devices
- 🌐 **CORS Configured** - Ready for production deployment

## 🎬 Quick Demo

```bash
# Clone and run in 3 commands
git clone https://github.com/yourusername/auth-system.git
cd auth-system/backend && go run main.go
# Open frontend/index.html in your browser - that's it! 🎉
```

## 📸 Screenshots

**Login Page**
- Clean, minimalist design
- Real-time form validation
- Smooth animations

**Dashboard**
- Protected route (JWT required)
- User-specific content
- Secure session management

## 🏗️ Architecture

```
┌─────────────┐          ┌─────────────┐          ┌─────────────┐
│   Browser   │  HTTPS   │  Go Server  │   TCP    │   MySQL DB  │
│  (Frontend) │ ◄──────► │  (Backend)  │ ◄──────► │  (Storage)  │
└─────────────┘          └─────────────┘          └─────────────┘
     │                          │
     │  JWT Token               │  bcrypt hash
     │  localStorage            │  Prepared statements
     └──────────────────────────┘
```

## 🛠️ Tech Stack

### Backend
```go
🔹 Go 1.25.3           // Performance & simplicity
🔹 Chi Router          // Lightweight, idiomatic routing
🔹 JWT (golang-jwt)    // Industry-standard tokens
🔹 bcrypt              // Adaptive password hashing
🔹 MySQL Driver        // Rock-solid database connectivity
```

### Frontend
```javascript
🔹 Vanilla JavaScript  // No framework overhead
🔹 Tailwind CSS        // Utility-first styling
🔹 Fetch API           // Modern HTTP requests
🔹 LocalStorage        // Client-side token persistence
```

## 📁 Project Structure

```
auth/
├── 📂 asset/              # Logos, icons, static files
├── 📂 backend/
│   ├── main.go           # 🚀 Server & API logic
│   └── go.mod            # Go dependencies
├── 📂 database/
│   └── auth.sql          # 🗄️ Database schema
└── 📂 frontend/
    ├── index.html        # 🔑 Login page
    ├── register.html     # 📝 Registration page
    ├── home.html         # 🏠 Protected dashboard
    └── script.js         # ⚡ Client-side magic
```

## 🚀 Getting Started

### Prerequisites

- **Go** 1.25.3+ ([Download](https://go.dev/dl/))
- **MySQL** 8.0+ ([Download](https://dev.mysql.com/downloads/))
- **Web Browser** (Chrome, Firefox, Safari, Edge)

### Installation

**1. Clone the repository**
```bash
git clone https://github.com/yourusername/auth-system.git
cd auth-system
```

**2. Set up the database**
```bash
# Login to MySQL
mysql -u root -p

# Create database and import schema
source database/auth.sql
```

**3. Configure the backend**

Edit `backend/main.go` line with your MySQL credentials:
```go
db, err = sql.Open("mysql", "root:your_password@tcp(localhost:3306)/auth")
```

**4. Install dependencies & run**
```bash
cd backend
go mod download
go run main.go
```

You should see:
```
Server is running on http://localhost:8080
```

**5. Launch the frontend**

Option A - Using VS Code Live Server:
- Install Live Server extension
- Right-click `frontend/index.html`
- Select "Open with Live Server"

Option B - Using Python:
```bash
cd frontend
python -m http.server 5500
```

**6. Start coding! 🎉**

Navigate to `http://localhost:5500` and create your first account!

## 🔌 API Reference

### Authentication Endpoints

#### **POST** `/auth` - Login
```json
Request:
{
  "username": "johndoe",
  "password_hash": "secretpass123"
}

Response (200):
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "message": "Login successful"
}
```

#### **POST** `/auth/register` - Register New User
```json
Request:
{
  "name": "John Doe",
  "username": "johndoe",
  "password_hash": "secretpass123"
}

Response (200):
{
  "success": "User registered successfully"
}
```

#### **GET** `/dashboard` - Protected Route
```http
Headers:
Authorization: Bearer <your_jwt_token>

Response (200):
{
  "message": "Welcome to dashboard"
}
```

## 🔒 Security Features

| Feature | Implementation | Why It Matters |
|---------|----------------|----------------|
| **Password Hashing** | bcrypt (cost: 14) | Prevents rainbow table attacks |
| **JWT Tokens** | HS256 signing | Stateless authentication |
| **CORS Protection** | Specific origin whitelist | Prevents unauthorized access |
| **SQL Injection** | Prepared statements | Database security |
| **Token Expiration** | Configurable TTL | Limits attack window |
| **HTTPS Ready** | TLS support | Encrypted communication |

## 🎓 Learning Resources

This project is perfect for understanding:

- ✅ How JWT authentication works end-to-end
- ✅ Go backend development with Chi router
- ✅ MySQL database integration
- ✅ Frontend-backend communication
- ✅ Security best practices
- ✅ RESTful API design

## 🔧 Configuration

### Environment Variables (Optional)
```bash
# Create .env file in backend/
DB_USER=root
DB_PASSWORD=yourpassword
DB_HOST=localhost
DB_PORT=3306
DB_NAME=auth
JWT_SECRET=your-secret-key
PORT=8080
```

### Database Schema
```sql
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    username VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(300) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## 🐛 Troubleshooting

**Problem:** `connection refused` error

**Solution:** Make sure MySQL is running: `sudo service mysql start`

---

**Problem:** CORS errors in browser console

**Solution:** Check that frontend is served on allowed origin (update `main.go` CORS settings)

---

**Problem:** JWT token expired

**Solution:** Login again to get a fresh token

## 🤝 Contributing

Contributions make the open-source world amazing! Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 💡 Future Enhancements

- [ ] Email verification
- [ ] Password reset functionality
- [ ] OAuth integration (Google, GitHub)
- [ ] Two-factor authentication (2FA)
- [ ] Rate limiting for API endpoints
- [ ] Redis for token blacklisting
- [ ] Docker containerization
- [ ] CI/CD pipeline
- [ ] Unit & integration tests

## 📝 License

Distributed under the MIT License. See `LICENSE` for more information.

## 👨‍💻 Author

**Saikat**

- GitHub: [@mdhsaikats](https://github.com/mdhsaikats)
- Portfolio: [Your Website]
- LinkedIn: [Your LinkedIn]

## 🌟 Show Your Support

Give a ⭐️ if this project helped you learn something new!

## 📚 Acknowledgments

- [Chi Router](https://github.com/go-chi/chi) - Lightweight Go router
- [JWT](https://jwt.io/) - Learn about JSON Web Tokens
- [Tailwind CSS](https://tailwindcss.com/) - Utility-first CSS framework
- [Go Documentation](https://go.dev/doc/) - Official Go docs

---

<p align="center">
  Made with ❤️ and ☕
</p>

<p align="center">
  <sub>Built to learn, shared to help others learn too!</sub>
</p>
#   A u t h e n t i c a t i o n - u s i n g - G o L a n g - J W T - P H - C H I  
 