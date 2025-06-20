import express from "express";
import mysql from "mysql2";
import multer from "multer";
import cors from "cors";
import path from "path";
import { v4 as uuidv4 } from 'uuid';
import bcrypt from "bcrypt";
import dotenv from "dotenv";
import nodemailer from "nodemailer";
import { v2 as cloudinary } from 'cloudinary';
import axios from "axios"; // Ensure axios is imported
import { createServer } from "http";

dotenv.config();

const app = express();
const router = express.Router();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors({
    origin: ["http://localhost:5173", "https://cotizador-git-version-secundaria-trxpjonys-projects.vercel.app", "https://vidrioalartesas.vercel.app"], // ✅ Permite también Vercel
    methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: true // ✅ Permite cookies y autenticación si las usas
}));
app.use(express.json());
const __dirname = path.resolve();
app.use("/img", express.static(path.join(__dirname, "../img")));

cloudinary.config({
    cloud_name: process.env.CLOUD_NAME, // Añade tus credenciales
    api_key: process.env.CLOUD_API_KEY,
    api_secret: process.env.CLOUD_API_SECRET,
});

// Multer configuration for file uploads
const storage = multer.memoryStorage(); // Usamos memoria en lugar de guardar el archivo localmente
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


// Define tus rutas sobre el router
router.get("/api/usuarios", (req, res) => {
    res.json({ msg: "Usuarios funcionando" });
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
    const SQL_QUERY = "SELECT id, usuario, rol FROM usuarios";
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


// Eliminar usuario
router.delete("/api/usuarios/:id", (req, res) => {
    const { id } = req.params;
    const SQL_QUERY = "DELETE FROM usuarios WHERE id = ?";
    DB.query(SQL_QUERY, [id], (err, result) => {
        if (err) {
            console.error("Error al eliminar usuario:", err);
            return res.status(500).json({ error: "Error al eliminar el usuario." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Usuario no encontrado." });
        }
        res.status(200).json({ message: "Usuario eliminado exitosamente." });
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

    // Verificar si hay un archivo para subir
    if (file) {
        cloudinary.uploader.upload_stream(
            {
                folder: "img_catalogo",
                public_id: `producto_${id}_${Date.now()}`,
                resource_type: "image",
                width: 643,
                height: 388,
                crop: "limit", // Esto mantiene la proporción y no recorta la imagen
            },
            (error, result) => {
                if (error) {
                    console.error("Error al subir la imagen a Cloudinary:", error);
                    return res.status(500).json({ error: "Error al subir la imagen a Cloudinary." });
                }

                console.log("Imagen subida a Cloudinary:", result.secure_url);
                actualizarProducto(id, title, description, precio, color, result.secure_url, categoria, res);
            }
        ).end(file.buffer);

    } else {
        // Si no hay imagen, actualizar sin modificar la imagen existente
        actualizarProducto(id, title, description, precio, color, null, categoria, res);
    }
});

// Crear producto y subir imagen a Cloudinary
router.post("/api/detalleProductos", upload.single("img"), async (req, res) => {
    const { title, description, precio, color, categoria } = req.body;
    const file = req.file;

    if (!title || !description || !precio || !color || !categoria || !file) {
        return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    // Subir imagen a Cloudinary
    cloudinary.uploader.upload_stream(
        {
            folder: "img_catalogo",
            public_id: `producto_${Date.now()}`,
            resource_type: "image",
            width: 643,
            height: 388,
            crop: "limit",
        },
        (error, result) => {
            if (error) {
                console.error("Error al subir la imagen a Cloudinary:", error);
                return res.status(500).json({ error: "Error al subir la imagen a Cloudinary." });
            }

            const imageUrl = result.secure_url;
            const id = uuidv4();

            // Guardar producto en la base de datos
            const SQL_INSERT = "INSERT INTO detalleproductos (id, title, description, color, precio, img, categoria) VALUES (?, ?, ?, ?, ?, ?, ?)";
            DB.query(SQL_INSERT, [id, title, description, color, precio, imageUrl, categoria], (err, dbResult) => {
                if (err) {
                    console.error("Error al guardar el producto:", err);
                    return res.status(500).json({ error: "Error al guardar el producto." });
                }
                res.status(201).json({ message: "Producto agregado correctamente", imageUrl });
            });
        }
    ).end(file.buffer);
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
    const SQL_QUERY = "DELETE FROM detalleproductos WHERE id = ?";
    DB.query(SQL_QUERY, [id], (err, result) => {
        if (err) {
            console.error("Error al eliminar el producto:", err);
            return res.status(500).json({ error: "Error al eliminar el producto." });
        }
        if (result.affectedRows === 0) {
            return res.status(404).json({ error: "Producto no encontrado." });
        }
        res.status(200).json({ message: "Producto eliminado exitosamente." });
    });
});


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


// Routes for quotations management
router.post("/api/cotizaciones", upload.single("pdf"), (req, res) => {
    const { cotNumber, client_name, email, usuario_id, total_precio, estado } = req.body; // Añadir estado
    const file = req.file;

    if (!cotNumber || !client_name || !email || !usuario_id || !file || !total_precio) {
        return res.status(400).json({ error: "Faltan datos para guardar la cotización" });
    }

    // Subir a Cloudinary
    cloudinary.uploader.upload_stream(
        {
            resource_type: "raw",
            public_id: `cotizaciones/${cotNumber}-${uuidv4()}`,
        },
        (error, result) => {
            if (error) {
                console.error("Error al subir el archivo a Cloudinary:", error);
                return res.status(500).json({ error: "Error al subir el archivo" });
            }

            const pdfUrl = result.secure_url;
            const imagePublicId = result.public_id;

            const SQL_INSERT = `
                INSERT INTO cotizaciones (cotNumber, client_name, pdf_path, email, total_precio, image_public_id, usuario_id, estado) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `;
            DB.query(SQL_INSERT, [cotNumber, client_name, pdfUrl, email, total_precio, imagePublicId, usuario_id, estado || 'pendiente'], (err, result) => {
                if (err) {
                    console.error("Error al guardar la cotización en la base de datos:", err);
                    return res.status(500).json({ error: "Error al guardar la cotización" });
                }
                res.json({ message: "Cotización almacenada con éxito", cotizacionId: result.insertId });
            });
        }
    ).end(file.buffer);
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

    // Obtener el public_id de la imagen antes de eliminar la cotización
    const SQL_GET_PUBLIC_ID = "SELECT image_public_id FROM cotizaciones WHERE id = ?";
    DB.query(SQL_GET_PUBLIC_ID, [id], (err, result) => {
        if (err) {
            console.error("Error al obtener el public_id de la cotización:", err);
            return res.status(500).json({ error: "Error al obtener el public_id de la cotización." });
        }
        if (result.length === 0) {
            return res.status(404).json({ error: "Cotización no encontrada." });
        }

        const imagePublicId = result[0].image_public_id;

        // Eliminar la cotización de la base de datos
        const SQL_DELETE = "DELETE FROM cotizaciones WHERE id = ?";
        DB.query(SQL_DELETE, [id], (err, result) => {
            if (err) {
                console.error("Error al eliminar la cotización:", err);
                return res.status(500).json({ error: "Error al eliminar la cotización." });
            }
            if (result.affectedRows === 0) {
                return res.status(404).json({ error: "Cotización no encontrada." });
            }

            // Eliminar la imagen de Cloudinary
            cloudinary.uploader.destroy(imagePublicId, { resource_type: "raw" }, (error, result) => { // Ensure resource_type is set to raw
                if (error) {
                    console.error("Error al eliminar documento de Cloudinary:", error);
                    return res.status(500).json({ error: "Error al eliminar documento de Cloudinary." });
                }
                res.status(200).json({ message: "Cotización eliminada exitosamente." });
            });
        });
    });
});

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
        const response = await axios.get(
            `https://api.cloudinary.com/v1_1/${process.env.CLOUD_NAME}/resources/image`,
            {
                auth: {
                    username: process.env.CLOUD_API_KEY,
                    password: process.env.CLOUD_API_SECRET,
                },
                params: {
                    type: "upload",
                    prefix: "blog", // Filter by the "blog" folder
                },
            }
        );
        res.json(response.data.resources);
    } catch (error) {
        console.error("Error al obtener imágenes de Cloudinary:", error);
        res.status(500).json({ error: "Error al obtener imágenes de Cloudinary" });
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

// Ruta para subir un nuevo post
router.post("/api/posts", upload.single("image"), (req, res) => {
    const { title, description, category } = req.body;
    const file = req.file;

    if (!title || !description || !category || !file) {
        return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    // Subir la imagen a Cloudinary en la carpeta "blog"
    cloudinary.uploader.upload_stream(
        {
            folder: "blog", // Guardar en la carpeta "blog"
            public_id: `post_${Date.now()}`,
            resource_type: "image",
        },
        (error, result) => {
            if (error) {
                console.error("Error al subir la imagen a Cloudinary:", error);
                return res.status(500).json({ error: "Error al subir la imagen." });
            }

            const imageUrl = result.secure_url;
            const imagePublicId = result.public_id; // Obtener el public_id de Cloudinary

            // Insertar el post en la base de datos
            const SQL_INSERT = `
                INSERT INTO posts (title, description, category, image, image_public_id) 
                VALUES (?, ?, ?, ?, ?)
            `;
            DB.query(SQL_INSERT, [title, description, category, imageUrl, imagePublicId], (err, dbResult) => {
                if (err) {
                    console.error("Error al guardar el post en la base de datos:", err);
                    return res.status(500).json({ error: "Error al guardar el post." });
                }
                res.status(201).json({ message: "Post creado exitosamente." });
            });
        }
    ).end(file.buffer);
});

router.delete("/api/posts/:id", (req, res) => {
    const { id } = req.params;

    // Obtener el public_id de la imagen antes de eliminar el post
    const SQL_GET_PUBLIC_ID = "SELECT image_public_id FROM posts WHERE id = ?";
    DB.query(SQL_GET_PUBLIC_ID, [id], (err, result) => {
        if (err) {
            console.error("Error al obtener el public_id del post:", err);
            return res.status(500).json({ error: "Error al obtener el public_id del post." });
        }
        if (result.length === 0) {
            return res.status(404).json({ error: "Post no encontrado." });
        }

        const imagePublicId = result[0].image_public_id;

        // Eliminar la imagen de Cloudinary
        cloudinary.uploader.destroy(imagePublicId, { resource_type: "image" }, (error) => {
            if (error) {
                console.error("Error al eliminar la imagen de Cloudinary:", error);
                return res.status(500).json({ error: "Error al eliminar la imagen de Cloudinary." });
            }

            // Eliminar el post de la base de datos
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
        });
    });
});

// Ruta para actualizar un post
router.put("/api/posts/:id", upload.single("image"), (req, res) => {
    const { id } = req.params;
    const { title, description, category } = req.body;
    const file = req.file;

    if (!title || !description || !category) {
        return res.status(400).json({ error: "Todos los campos son obligatorios." });
    }

    // Obtener el public_id de la imagen antigua
    const SQL_GET_PUBLIC_ID = "SELECT image_public_id FROM posts WHERE id = ?";
    DB.query(SQL_GET_PUBLIC_ID, [id], (err, result) => {
        if (err) {
            console.error("Error al obtener el public_id del post:", err);
            return res.status(500).json({ error: "Error al obtener el public_id del post." });
        }
        if (result.length === 0) {
            return res.status(404).json({ error: "Post no encontrado." });
        }

        const oldImagePublicId = result[0].image_public_id;

        // Si se sube una nueva imagen, subirla a Cloudinary
        if (file) {
            cloudinary.uploader.upload_stream(
                {
                    folder: "blog",
                    public_id: `post_${Date.now()}`,
                    resource_type: "image",
                },
                (error, uploadResult) => {
                    if (error) {
                        console.error("Error al subir la nueva imagen a Cloudinary:", error);
                        return res.status(500).json({ error: "Error al subir la nueva imagen." });
                    }

                    const newImageUrl = uploadResult.secure_url;
                    const newImagePublicId = uploadResult.public_id;

                    // Actualizar el post en la base de datos
                    actualizarPost(id, title, description, category, newImageUrl, newImagePublicId, res);

                    // Eliminar la imagen antigua de Cloudinary
                    cloudinary.uploader.destroy(oldImagePublicId, { resource_type: "image" }, (deleteError) => {
                        if (deleteError) {
                            console.error("Error al eliminar la imagen antigua de Cloudinary:", deleteError);
                        } else {
                            console.log("Imagen antigua eliminada de Cloudinary:", oldImagePublicId);
                        }
                    });
                }
            ).end(file.buffer);
        } else {
            // Si no se sube una nueva imagen, actualizar solo los demás campos
            actualizarPost(id, title, description, category, null, null, res);
        }
    });
});

// Función para actualizar el post en la base de datos
const actualizarPost = (id, title, description, category, imageUrl, imagePublicId, res) => {
    let SQL_QUERY;
    let queryParams;

    if (imageUrl && imagePublicId) {
        SQL_QUERY = "UPDATE posts SET title = ?, description = ?, category = ?, image = ?, image_public_id = ? WHERE id = ?";
        queryParams = [title, description, category, imageUrl, imagePublicId, id];
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
