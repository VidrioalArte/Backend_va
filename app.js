import express from "express";
import mysql from "mysql2";
import multer from "multer";
import cors from "cors";
import path from "path";
import { v4 as uuidv4 } from 'uuid';
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import axios from "axios"; // Ensure axios is imported
import { createServer } from "http";
import fs from "fs"; // Agrega esta línea al inicio

dotenv.config();

const app = express();
const router = express.Router();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors({
    origin: [
        "http://localhost:5173",
        "https://cotizador-git-version-secundaria-trxpjonys-projects.vercel.app",
        "https://vidrioalartesas.vercel.app",
        "https://www.vidrioalarte.com", // 👈 Agrega esto
        "https://vidrioalarte.com"      // También recomendable
    ],
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true
}));

app.use(express.json());

const __dirname = path.resolve();
app.use("/uploads", express.static(path.join(__dirname, "public/uploads")));


const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, path.join(__dirname, "public/uploads/img_catalogo")); // Ruta absoluta
    },
    filename: function (req, file, cb) {
        const uniqueName = `producto_${Date.now()}${path.extname(file.originalname)}`;
        cb(null, uniqueName);
    }
});

const upload = multer({ storage });


// Nodemailer configuration
const userGmail = "vidrioalarteemails@gmail.com";
const passAppGmail = "zmmr sive fdbs psgh";
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: userGmail,
        pass: passAppGmail,
    },
});

// Database configuration for railway
const DB = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
});

DB.connect((err) => {
    if (err) {
        console.error("❌ Error connecting to database:", err);
        return;
    }
    console.log("✅ Conexión exitosa a la base de datos en Railway 🚀");
});


// Obtener un usuario por nombre de usuario
router.get("/api/usuarios/:usuario", (req, res) => {
    const { usuario } = req.params;
    if (!usuario) {
        return res.status(400).send("El parámetro 'usuario' es necesario.");
    }
    const SQL_QUERY = "SELECT id, usuario, rol FROM usuarios WHERE LOWER(usuario) = LOWER(?)";
    DB.query(SQL_QUERY, [usuario], (err, result) => {
        if (err) {
            console.error("Error en la consulta SQL:", err);
            return res.status(500).send("Error al obtener los detalles del usuario.");
        }
        if (result.length === 0) {
            return res.status(404).send("Usuario no encontrado.");
        }
        res.json(result[0]);
    });
});

// Obtener todos los usuarios
router.get("/api/usuarios", (req, res) => {
    const SQL_QUERY = "SELECT id, usuario, rol FROM usuarios WHERE estado = 'activo'";
    DB.query(SQL_QUERY, (err, result) => {
        if (err) {
            console.error("Error en la consulta SQL:", err);
            return res.status(500).send("Error al obtener los usuarios.");
        }
        res.json(result);
    });
});

// Login con verificación de contraseña encriptada
router.post("/api/vidrioalarte/login", (req, res) => {
    const { usuario, contraseña } = req.body;
    if (!usuario || !contraseña) {
        return res.status(400).send("Usuario y contraseña son requeridos.");
    }

    const SQL_QUERY = "SELECT * FROM usuarios WHERE LOWER(usuario) = LOWER(?)";

    DB.query(SQL_QUERY, [usuario], async (err, result) => {
        if (err) {
            console.error("Error en la consulta SQL:", err);
            return res.status(500).send("Error al realizar el login.");
        }

        if (result.length === 0) {
            return res.status(401).send("Usuario o contraseña incorrectos.");
        }

        const user = result[0];

        // ⚠️ Validar estado
        if (user.estado !== "activo") {
            return res.status(403).send("Este usuario está inactivo. Contacta al administrador.");
        }

        // Comparar la contraseña usando bcrypt
        const validPassword = await bcrypt.compare(contraseña, user.contraseña);
        if (!validPassword) {
            return res.status(401).send("Usuario o contraseña incorrectos.");
        }

        res.send("Login exitoso.");
    });
});


// Actualizar usuario con contraseña encriptada
router.put("/api/usuarios/:id", async (req, res) => {
    const { id } = req.params;
    let { usuario, contraseña } = req.body;

    if (!usuario && !contraseña) {
        return res.status(400).json({ error: "Se requiere al menos un campo para actualizar." });
    }

    try {
        // 1️⃣ Obtener los datos actuales del usuario
        const SQL_GET_USER = "SELECT usuario, contraseña, rol FROM usuarios WHERE id = ?";
        DB.query(SQL_GET_USER, [id], async (err, results) => {
            if (err) {
                console.error("Error al obtener el usuario:", err);
                return res.status(500).json({ error: "Error al obtener el usuario" });
            }
            if (results.length === 0) {
                return res.status(404).json({ error: "Usuario no encontrado" });
            }

            const existingUser = results[0];

            // 2️⃣ Mantener los valores existentes si no se proporcionan nuevos
            usuario = usuario || existingUser.usuario;
            let newPassword = existingUser.contraseña; // Mantener la contraseña actual por defecto

            if (contraseña) {
                newPassword = await bcrypt.hash(contraseña, 10);
            }

            // 3️⃣ Realizar la actualización sin perder datos
            const SQL_UPDATE = "UPDATE usuarios SET usuario = ?, contraseña = ?, rol = ? WHERE id = ?";
            DB.query(SQL_UPDATE, [usuario, newPassword, existingUser.rol, id], (updateErr, updateResults) => {
                if (updateErr) {
                    console.error("Error al actualizar el usuario:", updateErr);
                    return res.status(500).json({ error: "Error al actualizar el usuario" });
                }
                if (updateResults.affectedRows === 0) {
                    return res.status(404).json({ error: "Usuario no encontrado" });
                }
                res.status(200).json({ message: "Usuario actualizado correctamente" });
            });
        });
    } catch (error) {
        console.error("Error al procesar la actualización:", error);
        res.status(500).json({ error: "Error interno del servidor." });
    }
});


// Desactivar usuario (en vez de eliminar)
router.delete("/api/usuarios/:id", (req, res) => {
    const { id } = req.params;
    const SQL_QUERY = "UPDATE usuarios SET estado = 'inactivo' WHERE id = ?";
    DB.query(SQL_QUERY, [id], (err, result) => {
        if (err) {
            console.error("Error al desactivar usuario:", err);
            return res.status(500).json({ error: "Error al desactivar el usuario." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Usuario no encontrado." });
        }
        res.status(200).json({ message: "Usuario desactivado exitosamente." });
    });
});

// Crear usuario con contraseña encriptada
router.post("/api/usuarios", async (req, res) => {
    const { usuario, contraseña, rol } = req.body;
    if (!usuario || !contraseña || !rol) {
        return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    try {
        const id = uuidv4();
        const hashedPassword = await bcrypt.hash(contraseña, 10);

        const SQL_QUERY = "INSERT INTO usuarios (id, usuario, contraseña, rol) VALUES (?, ?, ?, ?)";
        DB.query(SQL_QUERY, [id, usuario, hashedPassword, rol], (err, result) => {
            if (err) {
                console.error("Error al agregar el usuario:", err);
                return res.status(500).json({ error: "Error al agregar el usuario." });
            }
            res.status(201).json({ message: "Usuario agregado exitosamente." });
        });
    } catch (error) {
        console.error("Error al encriptar la contraseña:", error);
        res.status(500).json({ error: "Error interno del servidor." });
    }
});

// Routes for catalog management
router.get("/api/catalogo", (req, res) => {
    const SQL_QUERY = "SELECT * FROM catalogo";
    DB.query(SQL_QUERY, (err, result) => {
        if (err) {
            console.error("Error en la consulta SQL:", err);
            return res.status(500).send("Error al obtener los datos del catálogo.");
        }
        res.json(result);
    });
});

router.get("/api/marcos", (req, res) => {
    const SQL_QUERY = "SELECT * FROM marcos";
    DB.query(SQL_QUERY, (err, result) => {
        if (err) {
            console.error("Error en la consulta SQL:", err);
            return res.status(500).send("Error al obtener los datos de los marcos.");
        }
        res.json(result);
    });
});

router.get("/api/categorias", (req, res) => {
    const SQL_QUERY = "SELECT * FROM categorias";
    DB.query(SQL_QUERY, (err, result) => {
        if (err) {
            console.error("Error en la consulta SQL:", err);
            return res.status(500).send("Error al obtener los datos de categorias.");
        }
        res.json(result);
    });
});

router.get("/api/detalleProductos", (req, res) => {
    const SQL_QUERY = "SELECT * FROM detalleproductos";
    DB.query(SQL_QUERY, (err, result) => {
        if (err) {
            console.error("Error en la consulta SQL:", err);
            return res.status(500).send("Error al obtener los datos de detalleproductos.");
        }
        res.json(result);
    });
});

router.get('/api/precios', (req, res) => {
    const SQL_QUERY = "SELECT * FROM precios";
    DB.query(SQL_QUERY, (err, result) => {
        if (err) {
            console.error("Error en la consulta SQL:", err);
            return res.status(500).send("Error al obtener los datos de precios.");
        }
        res.json(result);
    });
});

router.put('/api/precios/:id', (req, res) => {
    const { id } = req.params;
    const { descripcion, precio } = req.body;
    const SQL_QUERY = "UPDATE precios SET descripcion = ?, precio = ? WHERE id = ?";
    DB.query(SQL_QUERY, [descripcion, precio, id], (err, result) => {
        if (err) {
            console.error("Error al actualizar el precio:", err);
            return res.status(500).json({ error: "Error al actualizar el precio." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Precio no encontrado." });
        }
        res.status(200).json({ message: "Precio actualizado exitosamente." });
    });
});

// Routes for product management
router.post("/productos", upload.single("image"), async (req, res) => {
    try {
        const imageUrl = req.file.path;
        const { title, description, color, precio, categoria } = req.body;
        const id = uuidv4();
        const SQL_INSERT = "INSERT INTO detalleproductos (id, title, description, color, precio, img, categoria) VALUES (?, ?, ?, ?, ?, ?, ?)";
        DB.query(SQL_INSERT, [id, title, description, color, precio, imageUrl, categoria], (err, result) => {
            if (err) {
                console.error("Error al insertar en la base de datos:", err);
                return res.status(500).json({ error: "Error al guardar el producto" });
            }
            res.status(201).json({ message: "Producto agregado correctamente", imageUrl });
        });
    } catch (error) {
        console.error("Error en la subida de imagen:", error);
        res.status(500).json({ error: "Error al subir la imagen" });
    }
});

router.put('/api/detalleProductos/:id', upload.single("img"), (req, res) => {
    const { id } = req.params;
    const { title, description, precio, color, categoria } = req.body;
    const file = req.file;

    if (!title || !description || !precio || !color || !categoria) {
        return res.status(400).json({ error: "Faltan datos para actualizar el producto." });
    }

    if (file) {
        // 1. Obtener la ruta de la imagen anterior
        const SQL_GET_IMG = "SELECT img FROM detalleproductos WHERE id = ?";
        DB.query(SQL_GET_IMG, [id], (err, result) => {
            if (err) {
                console.error("Error al obtener la imagen anterior:", err);
                return res.status(500).json({ error: "Error al obtener la imagen anterior." });
            }
            if (result.length === 0) {
                return res.status(404).json({ error: "Producto no encontrado." });
            }

            const oldImgPath = result[0].img;
            // Eliminar la imagen anterior si es local
            if (oldImgPath && oldImgPath.startsWith(process.env.BASE_URL ? process.env.BASE_URL : "")) {
                const relativePath = oldImgPath.replace(process.env.BASE_URL, "");
                const absolutePath = path.join(__dirname, "public", relativePath);
                fs.unlink(absolutePath, (fsErr) => {
                    if (fsErr && fsErr.code !== "ENOENT") {
                        console.error("Error al eliminar la imagen anterior:", fsErr);
                        // No retornes aquí, continúa con la actualización
                    }
                    // 2. Guardar la nueva imagen y actualizar el registro
                    const newImgUrl = `${process.env.BASE_URL}/uploads/img_catalogo/${file.filename}`;
                    actualizarProducto(id, title, description, precio, color, newImgUrl, categoria, res);
                });
            } else {
                // Si no hay imagen anterior o es externa, solo actualiza con la nueva imagen
                const newImgUrl = `${process.env.BASE_URL}/uploads/img_catalogo/${file.filename}`;
                actualizarProducto(id, title, description, precio, color, newImgUrl, categoria, res);
            }
        });
    } else {
        // Si no hay nueva imagen, actualizar solo los demás campos
        actualizarProducto(id, title, description, precio, color, null, categoria, res);
    }
});

// Crear producto y subir imagen 
router.post("/api/detalleProductos", upload.single("img"), async (req, res) => {
    const { title, description, precio, color, categoria } = req.body;
    const file = req.file;

    if (!title || !description || !precio || !color || !categoria || !file) {
        return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    const imageUrl = `${process.env.BASE_URL}/uploads/img_catalogo/${file.filename}`;
    const id = uuidv4();

    const SQL_INSERT = "INSERT INTO detalleproductos (id, title, description, color, precio, img, categoria) VALUES (?, ?, ?, ?, ?, ?, ?)";
    DB.query(SQL_INSERT, [id, title, description, color, precio, imageUrl, categoria], (err, dbResult) => {
        if (err) {
            console.error("Error al guardar el producto:", err);
            return res.status(500).json({ error: "Error al guardar el producto." });
        }
        res.status(201).json({ message: "Producto agregado correctamente", imageUrl });
    });
});

// Función para actualizar la base de datos
const actualizarProducto = (id, title, description, precio, color, imgUrl, categoria, res) => {
    let SQL_QUERY;
    let queryParams;

    if (imgUrl) {
        SQL_QUERY = "UPDATE detalleproductos SET title = ?, description = ?, precio = ?, color = ?, img = ?, categoria = ? WHERE id = ?";
        queryParams = [title, description, precio, color, imgUrl, categoria, id];
    } else {
        SQL_QUERY = "UPDATE detalleproductos SET title = ?, description = ?, precio = ?, color = ?, categoria = ? WHERE id = ?";
        queryParams = [title, description, precio, color, categoria, id];
    }

    DB.query(SQL_QUERY, queryParams, (err, result) => {
        if (err) {
            console.error("Error al actualizar el producto:", err);
            return res.status(500).json({ error: "Error al actualizar el producto." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Producto no encontrado." });
        }
        res.status(200).json({ message: "Producto actualizado exitosamente." });
    });
};


router.delete('/api/detalleProductos/:id', (req, res) => {
    const { id } = req.params;
    // 1. Obtener la ruta de la imagen antes de eliminar el producto
    const SQL_GET_IMG = "SELECT img FROM detalleproductos WHERE id = ?";
    DB.query(SQL_GET_IMG, [id], (err, result) => {
        if (err) {
            console.error("Error al obtener la imagen del producto:", err);
            return res.status(500).json({ error: "Error al obtener la imagen del producto." });
        }
        if (result.length === 0) {
            return res.status(404).json({ error: "Producto no encontrado." });
        }

        const imgPath = result[0].img;
        // Solo eliminar si la imagen existe y es local (no URL externa)
        if (imgPath && imgPath.startsWith(process.env.BASE_URL ? process.env.BASE_URL : "")) {
            // Extraer la ruta relativa al archivo
            const relativePath = imgPath.replace(process.env.BASE_URL, "");
            const absolutePath = path.join(__dirname, "public", relativePath);

            fs.unlink(absolutePath, (fsErr) => {
                if (fsErr && fsErr.code !== "ENOENT") {
                    console.error("Error al eliminar la imagen del producto:", fsErr);
                    // No retornes aquí, intenta eliminar el registro igual
                }
                // 2. Eliminar el registro de la base de datos
                eliminarProductoDB(id, res);
            });
        } else {
            // Si no hay imagen o es externa, solo elimina el registro
            eliminarProductoDB(id, res);
        }
    });
});

// Función auxiliar para eliminar el producto de la base de datos
function eliminarProductoDB(id, res) {
    const SQL_DELETE = "DELETE FROM detalleproductos WHERE id = ?";
    DB.query(SQL_DELETE, [id], (err, result) => {
        if (err) {
            console.error("Error al eliminar el producto:", err);
            return res.status(500).json({ error: "Error al eliminar el producto." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Producto no encontrado." });
        }
        res.status(200).json({ message: "Producto eliminado exitosamente." });
    });
};


// Endpoint para obtener categorías únicas de detalleProductos
router.get("/api/detalleProductos/categorias", (req, res) => {
    const SQL_QUERY = "SELECT DISTINCT categoria FROM detalleproductos WHERE categoria IS NOT NULL AND categoria != ''";
    DB.query(SQL_QUERY, (err, result) => {
        if (err) {
            console.error("Error al obtener categorías únicas:", err);
            return res.status(500).json({ error: "Error al obtener las categorías." });
        }
        // Devuelve solo el array de strings
        const categorias = result.map(row => row.categoria);
        res.json(categorias);
    });
});


// Rutas para manejar las cotizaciones
router.post("/api/cotizaciones", (req, res, next) => {
    // Usa un middleware multer específico para cotizaciones
    const cotizacionStorage = multer.diskStorage({
        destination: function (req, file, cb) {
            cb(null, path.join(__dirname, "public/uploads/cotizaciones"));
        },
        filename: function (req, file, cb) {
            const uniqueName = `cotizacion_${Date.now()}${path.extname(file.originalname)}`;
            cb(null, uniqueName);
        }
    });
    const uploadCotizacion = multer({ storage: cotizacionStorage }).single("pdf");
    uploadCotizacion(req, res, function (err) {
        if (err) {
            console.error("Error al guardar el archivo PDF:", err);
            return res.status(500).json({ error: "Error al guardar el archivo PDF." });
        }
        next();
    });
}, (req, res) => {
    const { cotNumber, client_name, email, usuario_id, total_precio, estado } = req.body;
    const file = req.file;

    if (!cotNumber || !client_name || !email || !usuario_id || !file || !total_precio) {
        return res.status(400).json({ error: "Faltan datos para guardar la cotización" });
    }

    // Construir la URL pública del archivo PDF
    const pdfUrl = `${process.env.BASE_URL}/uploads/cotizaciones/${file.filename}`;

    const SQL_INSERT = `
        INSERT INTO cotizaciones (cotNumber, client_name, pdf_path, email, total_precio, usuario_id, estado) 
        VALUES (?, ?, ?, ?, ?, ?, ?)
    `;
    DB.query(SQL_INSERT, [cotNumber, client_name, pdfUrl, email, total_precio, usuario_id, estado || 'pendiente'], (err, result) => {
        if (err) {
            console.error("Error al guardar la cotización en la base de datos:", err);
            return res.status(500).json({ error: "Error al guardar la cotización" });
        }
        res.json({ message: "Cotización almacenada con éxito", cotizacionId: result.insertId });
    });
});

router.get("/api/cotizaciones", (req, res) => {
    const SQL_QUERY = `
        SELECT 
            c.id, 
            c.cotNumber, 
            c.client_name, 
            c.pdf_path, 
            c.email, 
            c.total_precio,
            c.created_at, 
            c.estado,
            u.usuario AS nombre_usuario
        FROM 
            cotizaciones c
        JOIN 
            usuarios u ON c.usuario_id = u.id;
    `;
    DB.query(SQL_QUERY, (err, result) => {
        if (err) {
            console.error("Error en la consulta SQL:", err);
            return res.status(500).send("Error al obtener las cotizaciones.");
        }
        res.json(result);
    });
});

router.patch("/api/cotizaciones/:id", (req, res) => {
    const cotizacionId = req.params.id;
    const { estado } = req.body;

    // Validar el estado recibido
    const estadosValidos = ['pendiente', 'facturada', 'cancelada'];
    if (!estadosValidos.includes(estado)) {
        return res.status(400).json({ message: "Estado inválido." });
    }

    const SQL_UPDATE = `UPDATE cotizaciones SET estado = ? WHERE id = ?`;

    DB.query(SQL_UPDATE, [estado, cotizacionId], (err, result) => {
        if (err) {
            console.error("Error al actualizar el estado:", err);
            return res.status(500).json({ message: "Error al actualizar el estado." });
        }

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: "Cotización no encontrada." });
        }

        res.json({ message: "Estado actualizado correctamente." });
    });
});


router.delete("/api/cotizaciones/:id", (req, res) => {
    const { id } = req.params;

    // Obtener la ruta del PDF antes de eliminar la cotización
    const SQL_GET_PDF = "SELECT pdf_path FROM cotizaciones WHERE id = ?";
    DB.query(SQL_GET_PDF, [id], (err, result) => {
        if (err) {
            console.error("Error al obtener la ruta del PDF de la cotización:", err);
            return res.status(500).json({ error: "Error al obtener la ruta del PDF de la cotización." });
        }
        if (result.length === 0) {
            return res.status(404).json({ error: "Cotización no encontrada." });
        }

        const pdfPath = result[0].pdf_path;
        // Solo eliminar si la ruta existe y es local
        if (pdfPath && pdfPath.startsWith(process.env.BASE_URL ? process.env.BASE_URL : "")) {
            const relativePath = pdfPath.replace(process.env.BASE_URL, "");
            const absolutePath = path.join(__dirname, "public", relativePath);

            fs.unlink(absolutePath, (fsErr) => {
                if (fsErr && fsErr.code !== "ENOENT") {
                    console.error("Error al eliminar el PDF de la cotización:", fsErr);
                    // No retornes aquí, intenta eliminar el registro igual
                }
                eliminarCotizacionDB(id, res);
            });
        } else {
            // Si no hay PDF o es externo, solo elimina el registro
            eliminarCotizacionDB(id, res);
        }
    });
});

// Función auxiliar para eliminar la cotización de la base de datos
function eliminarCotizacionDB(id, res) {
    const SQL_DELETE = "DELETE FROM cotizaciones WHERE id = ?";
    DB.query(SQL_DELETE, [id], (err, result) => {
        if (err) {
            console.error("Error al eliminar la cotización:", err);
            return res.status(500).json({ error: "Error al eliminar la cotización." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Cotización no encontrada." });
        }
        res.status(200).json({ message: "Cotización eliminada exitosamente." });
    });
};

router.post("/api/send-email", upload.single("pdf"), (req, res) => {
    const { email, cotNumber } = req.body;
    const file = req.file;

    if (!email || !cotNumber || !file) {
        return res.status(400).json({ error: "Faltan datos para enviar el correo" });
    }

    const mailOptions = {
        from: userGmail,
        to: email,
        subject: `📄 Cotización #${cotNumber}`,
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; padding: 20px; border: 1px solid #ddd; border-radius: 10px;">
                <h2 style="color: #008cba; text-align: center;">Vidrio al Arte SAS</h2>
                <p>Estimado cliente,</p>
                <p>Adjunto encontrará el archivo correspondiente a la cotización <strong>#${cotNumber}</strong>.</p>
                <p>Si tiene alguna pregunta o desea más información, no dude en ponerse en contacto con nosotros.</p>
                <p>Atentamente,</p>
                <p><strong>Vidrio al Arte SAS</strong></p>
                <hr>
                <p style="font-size: 12px; color: #777;">Este es un correo generado automáticamente. Por favor, no responda a este mensaje.</p>
            </div>
        `,
        attachments: [
            {
                filename: `${cotNumber}.pdf`,
                content: file.buffer
            }
        ]
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error("Error al enviar el correo:", error);
            return res.status(500).json({ error: "Error al enviar el correo" });
        }
        res.json({ message: "Correo enviado con éxito", info });
    });
});


//obtener imagenes de la carpeta blog
router.get('/api/blog-images', async (req, res) => {
    try {
        const blogDir = path.join(__dirname, "public/uploads/blog");
        fs.readdir(blogDir, (err, files) => {
            if (err) {
                console.error("Error al leer la carpeta de imágenes del blog:", err);
                return res.status(500).json({ error: "Error al leer la carpeta de imágenes del blog" });
            }
            // Filtrar solo archivos de imagen comunes
            const imageFiles = files.filter(file =>
                /\.(jpg|jpeg|png|gif|webp|bmp)$/i.test(file)
            );
            // Construir URLs públicas
            const imageUrls = imageFiles.map(file =>
                `${process.env.BASE_URL}/uploads/blog/${file}`
            );
            res.json(imageUrls);
        });
    } catch (error) {
        console.error("Error al obtener imágenes del blog:", error);
        res.status(500).json({ error: "Error al obtener imágenes del blog" });
    }
});

// Route to fetch posts from the database
router.get("/api/posts", (req, res) => {
    const SQL_QUERY = "SELECT * FROM posts ORDER BY fecha DESC";
    DB.query(SQL_QUERY, (err, result) => {
        if (err) {
            console.error("Error fetching posts:", err);
            return res.status(500).json({ error: "Error fetching posts from the database." });
        }
        res.json(result);
    });
});

// Ruta para subir un nuevo post (imagen local en /uploads/blog)
router.post("/api/posts", (req, res, next) => {
    // Multer específico para blog
    const blogStorage = multer.diskStorage({
        destination: function (req, file, cb) {
            cb(null, path.join(__dirname, "public/uploads/blog"));
        },
        filename: function (req, file, cb) {
            const uniqueName = `post_${Date.now()}${path.extname(file.originalname)}`;
            cb(null, uniqueName);
        }
    });
    const uploadBlog = multer({ storage: blogStorage }).single("image");
    uploadBlog(req, res, function (err) {
        if (err) {
            console.error("Error al guardar la imagen del post:", err);
            return res.status(500).json({ error: "Error al guardar la imagen del post." });
        }
        next();
    });
}, (req, res) => {
    const { title, description, category } = req.body;
    const file = req.file;

    if (!title || !description || !category || !file) {
        return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    // Construir la URL pública de la imagen
    const imageUrl = `${process.env.BASE_URL}/uploads/blog/${file.filename}`;

    // Insertar el post en la base de datos
    const SQL_INSERT = `
        INSERT INTO posts (title, description, category, image) 
        VALUES (?, ?, ?, ?)
    `;
    DB.query(SQL_INSERT, [title, description, category, imageUrl], (err, dbResult) => {
        if (err) {
            console.error("Error al guardar el post en la base de datos:", err);
            return res.status(500).json({ error: "Error al guardar el post." });
        }
        res.status(201).json({ message: "Post creado exitosamente." });
    });
});

router.delete("/api/posts/:id", (req, res) => {
    const { id } = req.params;

    // Obtener la ruta de la imagen antes de eliminar el post
    const SQL_GET_IMG = "SELECT image FROM posts WHERE id = ?";
    DB.query(SQL_GET_IMG, [id], (err, result) => {
        if (err) {
            console.error("Error al obtener la imagen del post:", err);
            return res.status(500).json({ error: "Error al obtener la imagen del post." });
        }
        if (result.length === 0) {
            return res.status(404).json({ error: "Post no encontrado." });
        }

        const imgPath = result[0].image;
        // Eliminar la imagen si es local
        if (imgPath && imgPath.startsWith(process.env.BASE_URL ? process.env.BASE_URL : "")) {
            const relativePath = imgPath.replace(process.env.BASE_URL, "");
            const absolutePath = path.join(__dirname, "public", relativePath);

            fs.unlink(absolutePath, (fsErr) => {
                if (fsErr && fsErr.code !== "ENOENT") {
                    console.error("Error al eliminar la imagen del post:", fsErr);
                    // No retornes aquí, intenta eliminar el registro igual
                }
                eliminarPostDB(id, res);
            });
        } else {
            // Si no hay imagen o es externa, solo elimina el registro
            eliminarPostDB(id, res);
        }
    });
});

// Función auxiliar para eliminar el post de la base de datos
function eliminarPostDB(id, res) {
    const SQL_DELETE = "DELETE FROM posts WHERE id = ?";
    DB.query(SQL_DELETE, [id], (err, result) => {
        if (err) {
            console.error("Error al eliminar el post:", err);
            return res.status(500).json({ error: "Error al eliminar el post." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Post no encontrado." });
        }
        res.status(200).json({ message: "Post eliminado exitosamente." });
    });
};

// Ruta para actualizar un post (remplazo de imagen local)
router.put("/api/posts/:id", (req, res, next) => {
    // Multer específico para blog
    const blogStorage = multer.diskStorage({
        destination: function (req, file, cb) {
            cb(null, path.join(__dirname, "public/uploads/blog"));
        },
        filename: function (req, file, cb) {
            const uniqueName = `post_${Date.now()}${path.extname(file.originalname)}`;
            cb(null, uniqueName);
        }
    });
    const uploadBlog = multer({ storage: blogStorage }).single("image");
    uploadBlog(req, res, function (err) {
        if (err) {
            console.error("Error al guardar la imagen del post:", err);
            return res.status(500).json({ error: "Error al guardar la imagen del post." });
        }
        next();
    });
}, (req, res) => {
    const { id } = req.params;
    const { title, description, category } = req.body;
    const file = req.file;

    if (!title || !description || !category) {
        return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    // Obtener la ruta de la imagen anterior
    const SQL_GET_IMG = "SELECT image FROM posts WHERE id = ?";
    DB.query(SQL_GET_IMG, [id], (err, result) => {
        if (err) {
            console.error("Error al obtener la imagen anterior del post:", err);
            return res.status(500).json({ error: "Error al obtener la imagen anterior del post." });
        }
        if (result.length === 0) {
            return res.status(404).json({ error: "Post no encontrado." });
        }

        const oldImgPath = result[0].image;

        if (file) {
            // Eliminar la imagen anterior si es local
            if (oldImgPath && oldImgPath.startsWith(process.env.BASE_URL ? process.env.BASE_URL : "")) {
                const relativePath = oldImgPath.replace(process.env.BASE_URL, "");
                const absolutePath = path.join(__dirname, "public", relativePath);
                fs.unlink(absolutePath, (fsErr) => {
                    if (fsErr && fsErr.code !== "ENOENT") {
                        console.error("Error al eliminar la imagen anterior del post:", fsErr);
                        // No retornes aquí, continúa con la actualización
                    }
                    // Guardar la nueva imagen y actualizar el registro
                    const newImgUrl = `${process.env.BASE_URL}/uploads/blog/${file.filename}`;
                    actualizarPostLocal(id, title, description, category, newImgUrl, res);
                });
            } else {
                // Si no hay imagen anterior o es externa, solo actualiza con la nueva imagen
                const newImgUrl = `${process.env.BASE_URL}/uploads/blog/${file.filename}`;
                actualizarPostLocal(id, title, description, category, newImgUrl, res);
            }
        } else {
            // Si no se sube una nueva imagen, actualizar solo los demás campos
            actualizarPostLocal(id, title, description, category, null, res);
        }
    });
});

// Función para actualizar el post en la base de datos (local)
function actualizarPostLocal(id, title, description, category, imageUrl, res) {
    let SQL_QUERY;
    let queryParams;

    if (imageUrl) {
        SQL_QUERY = "UPDATE posts SET title = ?, description = ?, category = ?, image = ? WHERE id = ?";
        queryParams = [title, description, category, imageUrl, id];
    } else {
        SQL_QUERY = "UPDATE posts SET title = ?, description = ?, category = ? WHERE id = ?";
        queryParams = [title, description, category, id];
    }

    DB.query(SQL_QUERY, queryParams, (err, result) => {
        if (err) {
            console.error("Error al actualizar el post:", err);
            return res.status(500).json({ error: "Error al actualizar el post." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Post no encontrado." });
        }
        res.status(200).json({ message: "Post actualizado exitosamente." });
    });
};

// enviar duda o pregunta a travez del formulario de contacto
router.post("/api/send-question", (req, res) => {
    const { nombre, apellido, email, telefono, mensaje } = req.body;

    if (!nombre || !apellido || !email || !mensaje) {
        return res.status(400).json({ error: "Faltan datos obligatorios" });
    }

    const mailOptions = {
        from: userGmail,
        to: userGmail,
        subject: `Nueva consulta de ${nombre} ${apellido}`,
        html: `
            <div style="font-family: Arial, sans-serif; padding: 20px;">
                <h2 style="color: #008cba;">Nueva pregunta desde el sitio web</h2>
                <p><strong>Nombre:</strong> ${nombre} ${apellido}</p>
                <p><strong>Correo:</strong> ${email}</p>
                <p><strong>Teléfono:</strong>${telefono}</p>
                <p><strong>Mensaje:</strong><br>${mensaje}</p>
                <hr />
                <p style="font-size: 12px; color: #777;">Enviado automáticamente desde el formulario de contacto.</p>
            </div>
        `
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.error("Error al enviar la pregunta:", error);
            return res.status(500).json({ error: "Error al enviar el correo" });
        }
        res.json({ message: "Pregunta enviada con éxito", info });
    });
});

app.use("/nodejsapp", router);

createServer(app).listen(port, () => {
    console.log(`Servidor corriendo en puerto ${port}`);
});

// Start server
export default app;
