const bcrypt = require("bcrypt");
const express = require("express");
const router = express.Router();
const passport = require("passport");
const localStrategy = require("passport-local").Strategy;
const pool = require("../db/pool");
const { body, validationResult } = require("express-validator");

// Middleware para verificar se o usuário está autenticado
function ensureAuthenticated(req, res, next) {
  console.log("ensureAuthenticated called", req.isAuthenticated());
  if (req.isAuthenticated() && req.user) {
    console.log("User is authenticated:", req.user); // Adicione esta linha para depuração
    return next();
  }
  res.redirect("/login");
}

router.get("/", async (req, res, next) => {
  // Se o usuário não estiver autenticado, exibe a página de login
  if (!req.isAuthenticated()) {
    return res.render("login"); // Certifique-se de ter a view login.ejs
  }

  try {
    // Se o usuário estiver autenticado, buscar suas mensagens
    const { rows: messages } = await pool.query(
      `SELECT 
        messages.id AS message_id, 
        messages.title, 
        messages.message, 
        messages.created_at 
      FROM 
        messages 
      WHERE 
        messages.user_id = $1`, [req.user.id]
    );

    // Renderiza a página principal com as mensagens do usuário
    res.render("index", { user: req.user, messages: messages });
  } catch (err) {
    next(err);
  }
});


router.get("/sign", (req, res) => {
  res.render("sign");
});

router.get("/member", ensureAuthenticated, (req, res) => {
  console.log("User in /member GET route:", req.user); // Adicione esta linha para depuração
  res.render("member", { user: req.user, message: null });
});

router.post(
  "/sign",
  [
    body("password_confirm")
      .custom((value, { req }) => {
        if (value != req.body.password) {
          throw new Error("Passwords do not match");
        }
        return true;
      })
      .withMessage("Passwords do not match"),
    body("username").notEmpty().withMessage("Username is required"),
    body("password")
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters long"),
  ],
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    bcrypt.hash(req.body.password, 10, async (err, hash) => {
      if (err) {
        console.log("Error:", err);
      }
      try {
        await pool.query(
          "INSERT INTO users (username, fullname, membership_status, password) VALUES ($1, $2, 'visitante', $3)",
          [req.body.username, req.body.fullname, hash]
        );
        res.redirect("/");
      } catch (err) {
        next(err);
      }
    });
  }
);

router.post("/", (req, res, next) => {
  passport.authenticate("local", (err, user) => {
    if (!user) {
      return res.redirect("/");
    }
    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }
      return res.redirect("/"); // Redireciona corretamente após o login
    });
  })(req, res, next);
});

router.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
  });
  res.redirect("/");
});

passport.use(
  new localStrategy(async (username, password, done) => {
    try {
      const { rows } = await pool.query(
        "SELECT * FROM users WHERE username = $1",
        [username]
      );
      const user = rows[0];

      if (!user) {
        return done(null, false, { message: "Incorrect username." });
      }

      const match = await bcrypt.compare(password, user.password);

      if (!match) {
        return done(null, false, { message: "Incorrect password." });
      }

      return done(null, user);
    } catch (err) {
      console.log("Error in localStrategy:", err); // Logar qualquer erro
      return done(err);
    }
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  console.log("Deserializing user with ID:", id); // Log para verificar o ID

  try {
    const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
      id,
    ]);
    const user = rows[0];
    console.log("Deserialized user:", user); // Adicione esta linha para depuração
    done(null, user);
  } catch (err) {
    done(err);
  }
});

const SECRET_CODE = 999;

router.post("/member", ensureAuthenticated, async (req, res, next) => {
  console.log("User in POST /member:", req.user); // Verifica se o usuário está presente
  const { code } = req.body;
  if (parseInt(code) === SECRET_CODE) {
    try {
      await pool.query(
        "UPDATE users SET membership_status = 'membro' WHERE id = $1",
        [req.user.id]
      );

      const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [
        req.user.id,
      ]);
      req.user = rows[0];

      res.render("member", {
        user: req.user,
        message: "You are now a member!",
      });
    } catch (err) {
      next(err);
    }
  } else {
    res.render("member", { user: req.user, message: "Invalid code" });
  }
});

router.post("/create", async (req, res, next) => {
  const { title, message } = req.body;
  try {
    // Inserir a mensagem no banco de dados
    await pool.query("INSERT INTO messages (title, message, user_id) VALUES ($1, $2, $3)", [
      title,
      message,
      req.user.id,
    ]);

    // Buscar todas as mensagens do usuário autenticado
    const { rows: messages } = await pool.query(
      `SELECT 
        messages.id AS message_id, 
        messages.title, 
        messages.message, 
        messages.created_at, 
        users.id AS user_id, 
        users.fullname, 
        users.username, 
        users.membership_status 
      FROM 
        messages 
      INNER JOIN 
        users 
      ON 
        messages.user_id = users.id
      WHERE 
        users.id = $1;`, [req.user.id]
    );

    console.log("Messages retrieved:", messages); // Log para verificar as mensagens

    // Renderizar a página inicial com as mensagens
    res.render("index", { user: req.user, messages: messages });
  } catch (err) {
    next(err);
  }
});

router.get("/messages", ensureAuthenticated, async (req, res, next) => {
  res.render("messages");
})



module.exports = router;
