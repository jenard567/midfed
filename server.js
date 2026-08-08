require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const RAILWAY_URL = process.env.RAILWAY_URL || "";
const TURNSTILE_SECRET = process.env.TURNSTILE_SECRET || "";
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || "";

app.set("trust proxy", 1);

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://challenges.cloudflare.com", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      frameSrc: ["https://challenges.cloudflare.com"],
      connectSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
    },
  },
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const limiter = rateLimit({
  windowMs: 60_000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, slow down." },
});
app.use(limiter);

app.use(express.static(path.join(__dirname, "public"), {
  index: false,
}));

app.get("/", (_req, res) => {
  const fs = require("fs");
  const htmlPath = path.join(__dirname, "public", "index.html");
  let html = fs.readFileSync(htmlPath, "utf8");
  html = html.replace("__TURNSTILE_SITE_KEY__", TURNSTILE_SITE_KEY);
  res.type("html").send(html);
});

app.post("/verify/:type", async (req, res) => {
  const token = req.body?.token;
  const verificationType = req.params.type; 
  if (!token) {
    return res.status(400).json({ error: "Missing token" });
  }

  if (!RAILWAY_URL) {
    return res.status(500).json({ error: "RAILWAY_URL not configured" });
  }

  try {
    const formData = new URLSearchParams();
    formData.append("secret", TURNSTILE_SECRET);
    formData.append("response", token);
    formData.append("remoteip", req.ip);

    const verifyRes = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      { method: "POST", body: formData }
    );

    const data = await verifyRes.json();

    if (!data.success) {
      return res.status(403).json({
        error: "Verification failed",
        codes: data["error-codes"] || [],
      });
    }

    return res.json({ success: true, redirect: `${RAILWAY_URL}?type=${verificationType}/hwidhi` });
  } catch (err) {
    console.error("Turnstile verification error:", err.message);
    return res.status(502).json({ error: "Verification service unavailable" });
  }
});

app.use((_req, res) => {
  const fs = require("fs");
  const htmlPath = path.join(__dirname, "public", "index.html");
  let html = fs.readFileSync(htmlPath, "utf8");
  html = html.replace("__TURNSTILE_SITE_KEY__", TURNSTILE_SITE_KEY);
  res.status(404).type("html").send(html);
});

app.listen(PORT, () => {
  console.log(`[cloudflare-landing] listening on :${PORT}`);
  console.log(`[cloudflare-landing] railway target → ${RAILWAY_URL || "(unset)"}`);
  if (!TURNSTILE_SECRET || !TURNSTILE_SITE_KEY) {
    console.warn("[cloudflare-landing] ⚠ TURNSTILE_SECRET or TURNSTILE_SITE_KEY not set — captcha will not work");
  }
});
