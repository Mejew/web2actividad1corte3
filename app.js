import express from "express";
import jwt from "jsonwebtoken";
import mysql from "mysql2";
import cookieParser from "cookie-parser";

const app = express();
const port = 2659;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); // Agregar el uso de cookieParser

// Conexión a la base de datos MySQL
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "root",
  database: "login",
});

db.connect((err) => {
  if (err) throw err;
  console.log("Conectado a la base de datos MySQL");
});

app.get("/api", (req, res) => {
  res.json({ message: "Express y JWT" });
});

// Endpoint para el inicio de sesión
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.redirect("/public/error.html");
  }
  db.query(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    [username, password],
    (err, result) => {
      if (err) {
        res.sendStatus(500); // Error interno del servidor
      } else {
        if (result.length > 0) {
          const user = {
            id: result[0].id,
            username: result[0].username,
          };

          jwt.sign(
            { user },
            "secretkey",
            { expiresIn: "120s" },
            (error, token) => {
              res.cookie("token", token, { httpOnly: true, maxAge: 120000 }); // Almacena el token en la cookie
              res.json({ token });
            }
          );
        } else {
          res.status(401).send("Credenciales inválidas");
        }
      }
    }
  );
});

// Ruta protegida
app.post("/api/protected", verifyToken, (req, res) => {
  jwt.verify(req.cookies.token, "secretkey", (error, authData) => {
    if (error) {
      res.sendStatus(403);
    } else {
      res.json({
        message: "Ruta protegida",
      });
    }
  });
});

function verifyToken(req, res, next) {
  const token = req.cookies.token;
  if (typeof token !== "undefined") {
    next();
  } else {
    res.sendStatus(403);
  }
}

app.listen(port, () => {
  console.log(`Servidor ejecutándose en el puerto ${port}`);
});
