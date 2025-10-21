Store Project Backend

A Node.js + Express + SQLite3 backend for managing users, stores, ratings, and authentication. Built with JWT-based authentication and role-based access control (ADMIN, OWNER, USER). Designed to work seamlessly with the Store Project frontend.

Features:

User signup, login, and JWT authentication

Role-based access control (ADMIN, OWNER, USER)

Admin can create users and stores, view dashboard stats

Owners can manage their stores and view ratings

Users can rate stores, update or delete ratings

Secure password hashing with bcrypt

Change password for logged-in users

SQLite3 database with automatic table creation and initial seeding

Tech Stack

Node.js

Express.js

SQLite3 (sqlite package)

bcrypt for password hashing

JSON Web Tokens (JWT)

CORS enabled

Getting Started
Prerequisites

Node.js (v16+)

npm



# Install dependencies
npm install

Environment Variables

Create a .env file in the root:

JWT_SECRET=your_secret_key_here
PORT=3000

Database

SQLite3 database file: dev.sqlite3

Tables auto-created on server start: users, stores, ratings

Initial seed data:

Admin: admin@example.com / Admin@123

Owner: owner@example.com / Owner@123

Default store linked to owner

Running the Server
node index.js

🔗 Project Links Frontend GitHub Repo: https://github.com/yashwanth843/store-frontend

Backend GitHub Repo: https://github.com/yashwanth843/StoreProject-Backend

Live Frontend Deployment: https://rating-store.netlify.app

live server link: https://storeproject-backend.onrender.com
Google Drive Link: https://drive.google.com/file/d/11vuwpSiogyYDQ9oY1VIQDJubUwCk5vdq/view?usp=sharing

API Endpoints
Authentication
Method	Endpoint	Description
POST	/api/auth/signup	Register a new user (USER role)
POST	/api/auth/login	Login and receive JWT token
Admin Routes (Requires ADMIN JWT)
Method	Endpoint	Description
GET	/api/admin/dashboard	Total users, stores, and ratings stats
POST	/api/admin/users	Create new user (ADMIN, USER, OWNER)
POST	/api/admin/stores	Create a new store
GET	/api/admin/users	List users with filters & sorting
GET	/api/admin/stores	List stores with average ratings
Store Routes
Method	Endpoint	Description
GET	/api/stores	List stores with average rating and user rating
GET	/api/stores/owner	Owners: list raters and average ratings
User Routes
Method	Endpoint	Description
POST	/api/user/change-password	Change password for logged-in user
Ratings
Method	Endpoint	Description
POST	/api/ratings	Submit or update rating (upsert)
DELETE	/api/ratings/:id	Delete rating (self or admin only)
Password Requirements

8–16 characters

Must include at least one uppercase letter

Must include at least one special character

CORS enabled for frontend integration

Make sure JWT_SECRET is set in production for security
