const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const path = require('path');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Al entrar a la raíz del sitio (/), mostrar directamente el login.
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'alexis-login.html'));
});

// Render te da esta variable de entorno automáticamente al crear
// la base de datos Postgres y conectarla a este servicio.
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

// Crea la tabla de usuarios si todavía no existe.
async function iniciarDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      email TEXT PRIMARY KEY,
      password TEXT NOT NULL,
      password_visible TEXT NOT NULL,
      creado_en TIMESTAMPTZ DEFAULT now()
    )
  `);
  console.log('Tabla "usuarios" lista.');
}

// ---- Registro ----
app.post('/registro', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Correo y contraseña son obligatorios.' });
  }

  try {
    const existente = await pool.query('SELECT 1 FROM usuarios WHERE email = $1', [email]);
    if (existente.rows.length > 0) {
      return res.status(409).json({ error: 'Ese correo ya está registrado.' });
    }

    // Se guarda el hash (para validar el login de forma segura) y también
    // la contraseña en texto plano en "password_visible", a pedido tuyo.
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO usuarios (email, password, password_visible) VALUES ($1, $2, $3)',
      [email, hash, password]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error del servidor al registrar.' });
  }
});

// ---- Login ----
app.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Correo y contraseña son obligatorios.' });
  }

  try {
    const resultado = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    const usuario = resultado.rows[0];

    if (!usuario) {
      return res.status(401).json({ error: 'Credenciales incorrectas.' });
    }

    const coincide = await bcrypt.compare(password, usuario.password);
    if (!coincide) {
      return res.status(401).json({ error: 'Credenciales incorrectas.' });
    }

    res.json({ ok: true, email: usuario.email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error del servidor al iniciar sesión.' });
  }
});

const PUERTO = process.env.PORT || 3000;

iniciarDB()
  .then(() => {
    app.listen(PUERTO, () => {
      console.log(`Servidor de Alexis corriendo en el puerto ${PUERTO}`);
    });
  })
  .catch((err) => {
    console.error('No se pudo conectar a la base de datos:', err);
  });