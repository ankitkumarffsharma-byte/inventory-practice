
require("dotenv").config();

const express = require("express");
const path = require("path");
const mongoose = require("mongoose");
const session = require("express-session");
const bcrypt = require("bcryptjs");

const Product = require("./models/Product");
const User = require("./models/User");

const app = express();

// EJS settings
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// Session settings
app.use(
    session({
        secret: process.env.SESSION_SECRET || "change-this-secret-in-env",
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            sameSite: "lax",
            secure: process.env.NODE_ENV === "production",
            maxAge: 60 * 60 * 1000
        }
    })
);

// LOGIN PAGE
app.get("/login", (req, res) => {
    if (req.session.userId) {
        return res.redirect("/");
    }

    res.render("login", { error: null });
});

// REGISTER PAGE
app.get("/register", (req, res) => {
    if (req.session.userId) {
        return res.redirect("/");
    }

    res.render("register", { error: null });
});

// REGISTER USER - NAME FIXED
app.post("/register", async (req, res) => {
    try {
        const name = String(req.body.name || "").trim();
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        if (!name || !email || password.length < 8) {
            return res.status(400).render("register", {
                error: "Name, valid email aur minimum 8-character password dalo."
            });
        }

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            return res.status(409).render("register", {
                error: "Ye email pehle se registered hai. Login karo."
            });
        }

        const hashedPassword = await bcrypt.hash(password, 12);

        await User.create({
            name: name,
            email: email,
            password: hashedPassword
        });

        return res.redirect("/login");
    } catch (error) {
        console.error("Register Error:", error.message);

        if (error.code === 11000) {
            return res.status(409).render("register", {
                error: "Ye email pehle se registered hai."
            });
        }

        return res.status(500).render("register", {
            error: "Account create nahi hua. Terminal mein error check karo."
        });
    }
});

// LOGIN USER
app.post("/login", async (req, res, next) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const password = String(req.body.password || "");

        const user = await User.findOne({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).render("login", {
                error: "Email ya password galat hai."
            });
        }

        req.session.regenerate((error) => {
            if (error) return next(error);

            req.session.userId = user._id.toString();
            req.session.userEmail = user.email;
            req.session.username = user.name;

            req.session.save((saveError) => {
                if (saveError) return next(saveError);
                res.redirect("/");
            });
        });
    } catch (error) {
        next(error);
    }
});

// PROTECT INVENTORY ROUTES
function requireLogin(req, res, next) {
    if (!req.session.userId) {
        return res.redirect("/login");
    }

    next();
}

app.use(requireLogin);

// DASHBOARD
app.get("/", async (req, res) => {
    try {
        const search = String(req.query.search || "").trim();

        const filter = search
            ? { name: { $regex: search, $options: "i" } }
            : {};

        const products = await Product.find(filter)
            .sort({ id: 1 })
            .lean();

        res.render("dashboard", {
            username: req.session.username || req.session.userEmail,
            products,
            search,
            chartNames: products.map(p => p.name),
            chartPrices: products.map(p => p.price)
        });
    } catch (error) {
        console.error("Dashboard Error:", error.message);
        res.status(500).send("Dashboard load nahi hua.");
    }
});

// ADD PRODUCT PAGE
app.get("/add-product", (req, res) => {
    res.render("add-product");
});

// ADD PRODUCT
app.post("/add-product", async (req, res) => {
    try {
        const name = String(req.body.name || "").trim();
        const price = Number(req.body.price);

        if (!name || !Number.isFinite(price) || price <= 0) {
            return res.status(400).send("Valid product name aur price dalo.");
        }

        const lastProduct = await Product.findOne().sort({ id: -1 });
        const nextId = lastProduct ? lastProduct.id + 1 : 1;

        await Product.create({ id: nextId, name, price });

        res.redirect("/");
    } catch (error) {
        console.error("Add Product Error:", error.message);
        res.status(500).send("Product save nahi ho paya.");
    }
});

// DELETE PRODUCT
app.post("/delete-product/:id", async (req, res) => {
    try {
        const id = Number(req.params.id);
        const product = await Product.findOneAndDelete({ id });

        if (!product) {
            return res.status(404).send("Product nahi mila.");
        }

        res.redirect("/");
    } catch (error) {
        console.error("Delete Error:", error.message);
        res.status(500).send("Product delete nahi hua.");
    }
});

// EDIT PRODUCT PAGE
app.get("/edit-product/:id", async (req, res) => {
    try {
        const id = Number(req.params.id);
        const product = await Product.findOne({ id }).lean();

        if (!product) {
            return res.status(404).send("Product nahi mila.");
        }

        res.render("edit-product", { product });
    } catch (error) {
        console.error("Edit Page Error:", error.message);
        res.status(500).send("Edit page load nahi hua.");
    }
});

// UPDATE PRODUCT
app.post("/edit-product/:id", async (req, res) => {
    try {
        const id = Number(req.params.id);
        const name = String(req.body.name || "").trim();
        const price = Number(req.body.price);

        if (!name || !Number.isFinite(price) || price <= 0) {
            return res.status(400).send("Valid name aur price dalo.");
        }

        const product = await Product.findOneAndUpdate(
            { id },
            { name, price },
            { new: true, runValidators: true }
        );

        if (!product) {
            return res.status(404).send("Product nahi mila.");
        }

        res.redirect("/");
    } catch (error) {
        console.error("Update Error:", error.message);
        res.status(500).send("Product update nahi hua.");
    }
});

// LOGOUT
app.post("/logout", (req, res, next) => {
    req.session.destroy((error) => {
        if (error) return next(error);

        res.clearCookie("connect.sid");
        res.redirect("/login");
    });
});

// ERROR HANDLER
app.use((error, req, res, next) => {
    console.error("Server Error:", error.message);
    res.status(500).send("Server mein error aaya. Terminal check karo.");
});

// START SERVER
mongoose.connect(
    process.env.MONGO_URI || "mongodb://127.0.0.1:27017/inventoryDB"
)
.then(() => {
    console.log("MongoDB Connected!");

    app.listen(3000, () => {
        console.log("Server running at http://localhost:3000");
    });
})
.catch((error) => {
    console.error("MongoDB Error:", error.message);
});
