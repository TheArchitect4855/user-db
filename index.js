const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const express = require("express");
const fs = require("fs");
const http = require("http");
const https = require("https");
const path = require("path");
const UserDb = require("./userdb");

require("dotenv").config();

let options = null;
try {
	options = {
		key: fs.readFileSync(process.env.HTTPS_KEY),
		cert: fs.readFileSync(process.env.HTTPS_CERT),
	};
} catch(e) {
	console.error("Could not read SSL certificates:");
	console.error(e);
}

const db = new UserDb(path.join(
	process.cwd(),
	"db"
)).index();

const app = express();
app.use(cookieParser());
app.use(express.json());

app.use((req, res, next) => {
    res.append('Access-Control-Allow-Origin', ['*']);
    res.append('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
    res.append('Access-Control-Allow-Headers', 'Content-Type,Authorization');
    next();
});

// User endpoint
app.post("/user", (req, res) => {
	const { email, password } = req.body;
	try {
		const { uid } = db.create(email, password);
		res.json(uid);
	} catch(e) {
		res.status(403).json({ error: e });
	}
});

app.get("/user", (req, res) => {
	const auth = decodeBasicAuth(req.headers.authorization);
	if(auth) {
		const { email, password } = auth;
		
		try {
			const { uid } = db.read(email, password);
			res.json(uid);
		} catch(e) {
			res.status(401).json({ error: e });
		}

	} else res.status(401).end();
});

app.put("/user", (req, res) => {
	const auth = decodeBasicAuth(req.headers.authorization);
	if(auth) {
		const { email, password } = auth;
		
		try {
			db.update(email, password, req.body);
			res.end();
		} catch(e) {
			console.dir(e);
			res.status(401).json({ error: e });
		}
	} else res.status(401).end();
});

app.delete("/user", (req, res) => {
	const auth = decodeBasicAuth(req.headers.authorization);
	if(auth) {
		const { email, password } = auth;
		
		try {
			db.delete(email, password);
			res.end();
		} catch(e) {
			console.dir(e);
			res.status(401).json({ error: e });
		}
	} else res.status(401).end();
});

// Login endpoint (ideally logins should be stateless but they aren't because I didn't wanna use JWTs)
const sessionKeys = {};
app.post("/login/", (req, res) => {
	const { email, password } = req.body;
	try {
		const user = db.read(email, password);

		let sessionKey = null;
		if(sessionKeys[user.uid]) {
			sessionKey = sessionKeys[user.uid];
		} else {
			sessionKey = crypto.randomBytes(16).toString("base64");
			sessionKeys[sessionKey] = user.uid;
			sessionKeys[user.uid] = sessionKey;
		}

		res.cookie("sessionKey", sessionKey).end();
	} catch(e) {
		res.status(401).json({ error: e });
	}
});

app.get("/login/", (req, res) => {
	const { sessionKey } = req.cookies;
	const uid = sessionKeys[sessionKey];
	if(uid) {
		const user = db.uidIndex[uid];
		res.json(user);
	} else res.status(403).end();
});

app.delete("/login/", (req, res) => {
	const { sessionKey } = req.cookies;
	const uid = sessionKeys[sessionKey];
	if(uid) {
		sessionKeys[sessionKey] = undefined;
		sessionKeys[uid] = undefined;
		res.end();
	} else res.status(403).end();
});

// Create server
if(options) {
	// Create HTTPS server
	const overridePort = process.env.HTTPS_PORT;
	const port = overridePort ? overridePort : 443;
	https.createServer(options, app)
		.listen(port, (err) => {
			if(err) {
				console.error("Error creating HTTPS server:");
				console.error(err);
			} else {
				console.log(`Listening at https://localhost:${port}`);
			}
		});
	
	// Create HTTP server that upgrades all connections
	const httpOverridePort = process.env.HTTP_PORT;
	const httpPort = httpOverridePort ? httpOverridePort : 80;
	http.createServer((req, res) => {
		res.statusCode = 301;
		res.setHeader("Location", "https://" + req.headers.host + req.url);
		res.end();
	}).listen(httpPort, (err) => {
		if(err) {
			console.error("Error creating HTTP server:");
			console.error(err);
		} else {
			console.log(`Listening at http://localhost:${port}`);
		}
	});
} else {

	// Create HTTP server
	const overridePort = process.env.HTTP_PORT;
	const port = overridePort ? overridePort : 80;
	http.createServer(app)
		.listen(port, (err) => {
			if(err) {
				console.error("Error creating HTTP server:");
				console.error(err);
			} else {
				console.log(`Listening at http://localhost:${port}`);
			}
		});	
}

function decodeBasicAuth(auth) {
	const basic = "Basic ";
	if(auth && auth.startsWith(basic)) {
		const login = Buffer.from(auth.substring(basic.length), "base64").toString();
		const email = login.split(":")[0];
		const password = login.substring(email.length + 1);
		return { email, password };
	} else return null;
}