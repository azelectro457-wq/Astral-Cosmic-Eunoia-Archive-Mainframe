
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("node:crypto");
const path = require("node:path");

const app = express();
const PORT = process.env.PORT || 3000;

const CLIENT_ID = process.env.GITHUB_CLIENT_ID;
const CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET;
const SESSION_SECRET = process.env.SESSION_SECRET;
const BASE_URL = process.env.APP_URL?.replace(/\/$/, "");

if (!CLIENT_ID || !CLIENT_SECRET || !SESSION_SECRET || !BASE_URL) {
  throw new Error(
    "Missing GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, " +
    "SESSION_SECRET, or APP_URL environment variable."
  );
}

if (process.env.NODE_ENV === "production" &&
    !BASE_URL.startsWith("https://")) {
  throw new Error("APP_URL must use HTTPS in production.");
}

app.set("trust proxy", 1);
app.disable("x-powered-by");

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "https://avatars.githubusercontent.com"],
      connectSrc: ["'self'"],
      baseUri: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"],
      formAction: ["'self'"]
    }
  }
}));

app.use(session({
  name: "github_dashboard_session",
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 8
  }
  // The default MemoryStore is for local demos only.
  // Configure a shared production session store before scaling.
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: "draft-8",
  legacyHeaders: false
});

app.use("/api", apiLimiter);

const publicDir = path.join(__dirname, "public");

function randomToken() {
  return crypto.randomBytes(32).toString("hex");
}

function requireLogin(req, res, next) {
  if (!req.session.user || !req.session.accessToken) {
    return res.status(401).json({
      error: "Please sign in with GitHub."
    });
  }

  next();
}

async function githubFetch(url, token) {
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "GitHub-User-Dashboard"
    },
    signal: AbortSignal.timeout(15000)
  });

  if (!response.ok) {
    const error = new Error(`GitHub API returned ${response.status}`);
    error.status = response.status;
    throw error;
  }

  return response.json();
}

app.get("/", (req, res) => {
  if (req.session.user) {
    return res.redirect("/dashboard");
  }

  res.sendFile(path.join(publicDir, "index.html"));
});

app.get("/auth/github", loginLimiter, (req, res) => {
  const state = randomToken();
  req.session.oauthState = state;

  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: `${BASE_URL}/auth/github/callback`,
    scope: "read:user",
    state
  });

  req.session.save((err) => {
    if (err) {
      return res.status(500).send("Unable to start sign-in.");
    }

    res.redirect(
      `https://github.com/login/oauth/authorize?${params}`
    );
  });
});

app.get("/auth/github/callback", async (req, res) => {
  const { code, state, error } = req.query;
  const expectedState = req.session.oauthState;

  delete req.session.oauthState;

  if (error) {
    return req.session.save(() => {
      res.redirect("/?error=authorization_denied");
    });
  }

  if (
    typeof code !== "string" ||
    typeof state !== "string" ||
    !expectedState ||
    !crypto.timingSafeEqual(
      Buffer.from(state),
      Buffer.from(expectedState)
    )
  ) {
    return res.status(400).send("Invalid OAuth state. Please try again.");
  }

  try {
    const tokenResponse = await fetch(
      "https://github.com/login/oauth/access_token",
      {
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          code,
          redirect_uri: `${BASE_URL}/auth/github/callback`
        }),
        signal: AbortSignal.timeout(15000)
      }
    );

    if (!tokenResponse.ok) {
      throw new Error("GitHub token exchange failed.");
    }

    const tokenData = await tokenResponse.json();

    if (tokenData.error || !tokenData.access_token) {
      throw new Error("GitHub did not issue an access token.");
    }

    const token = tokenData.access_token;
    const githubUser = await githubFetch(
      "https://api.github.com/user",
      token
    );

    // Prevent session fixation after successful authentication.
    const user = {
      id: githubUser.id,
      login: githubUser.login
    };

    await new Promise((resolve, reject) => {
      req.session.regenerate((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    req.session.user = user;
    req.session.accessToken = token;

    await new Promise((resolve, reject) => {
      req.session.save((err) => {
        if (err) reject(err);
        else resolve();
      });
    });

    res.redirect("/dashboard");
  } catch (err) {
    console.error("OAuth callback failed:", err.message);
    res.status(502).send(
      "GitHub sign-in failed. Please return to the home page and try again."
    );
  }
});

app.get("/dashboard", requireLogin, (req, res) => {
  res.sendFile(path.join(publicDir, "dashboard.html"));
});

app.get("/api/me", requireLogin, async (req, res) => {
  try {
    const user = await githubFetch(
      "https://api.github.com/user",
      req.session.accessToken
    );

    // Return only fields needed by the dashboard.
    res.set("Cache-Control", "no-store");
    res.json({
      login: user.login,
      name: user.name,
      avatar_url: user.avatar_url,
      html_url: user.html_url,
      bio: user.bio,
      location: user.location,
      public_repos: user.public_repos,
      followers: user.followers,
      following: user.following
    });
  } catch (err) {
    console.error("Profile request failed:", err.message);
    res.status(err.status === 401 ? 401 : 502).json({
      error: "Could not load your GitHub profile."
    });
  }
});

app.get("/api/repos", requireLogin, async (req, res) => {
  try {
    // Use the authenticated user's own login, not a query parameter.
    const login = req.session.user.login;
    const repos = await githubFetch(
      "https://api.github.com/user/repos?visibility=public" +
      "&affiliation=owner&sort=updated&per_page=100",
      req.session.accessToken
    );

    res.set("Cache-Control", "no-store");
    res.json(repos.map((repo) => ({
      id: repo.id,
      name: repo.name,
      description: repo.description,
      html_url: repo.html_url,
      language: repo.language,
      stargazers_count: repo.stargazers_count,
      forks_count: repo.forks_count,
      updated_at: repo.updated_at,
      owner: repo.owner.login
    })).filter((repo) => repo.owner === login));
  } catch (err) {
    console.error("Repository request failed:", err.message);
    res.status(err.status === 401 ? 401 : 502).json({
      error: "Could not load your repositories."
    });
  }
});

app.post("/auth/logout", requireLogin, (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).json({
        error: "Unable to sign out."
      });
    }

    res.clearCookie("github_dashboard_session", {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/"
    });

    res.json({ success: true });
  });
});

app.use(express.static(publicDir, {
  index: false,
  dotfiles: "deny"
}));

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Dashboard server listening on port ${PORT}`);
});
