const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const uuid = require("uuid");

/**
 * User: {
 * 		uid,
 * 		eml,
 * 		pwd,
 * 		slt,
 * }
 */

module.exports = class UserDb {
	constructor(dir) {
		if(!fs.existsSync(dir)) fs.mkdirSync(dir);

		this.dir = dir;
		this.files = fs.readdirSync(dir);
		console.log(`UserDb found files: ${JSON.stringify(this.files)}`);
	}

	index() {
		const uidIndex = {};
		const emlIndex = {};
		for(const file of this.files) {
			const users = JSON.parse(
				fs.readFileSync(
					path.join(this.dir, file)
				)
			);

			for(const user of users) {
				uidIndex[user.uid] = user;
				emlIndex[user.eml] = user.uid;
			}
		}

		return new IndexedUserDb(uidIndex, emlIndex, this);
	}
}

class IndexedUserDb {
	#userDb;

	constructor(uidIndex, emlIndex, userDb) {
		this.uidIndex = uidIndex;
		this.emlIndex = emlIndex;
		this.#userDb = userDb;
	}

	create(email, password) {
		const eml = this.standardizeEmail(email);
		if(this.emlIndex[eml]) {
			throw `User ${eml} already exists.`;
		}

		const slt = crypto.randomBytes(32).toString("base64");
		const pwd = this.hashPassword(password, slt);
		const uid = uuid.v4();
		const user = {
			uid,
			eml,
			pwd,
			slt,
		};

		this.uidIndex[uid] = user;
		this.emlIndex[eml] = uid;
		this.#saveUser(user);

		return user;
	}

	read(email, password) {
		const eml = this.standardizeEmail(email);
		if(this.emlIndex[eml] == undefined) {
			throw `User ${eml} does not exist.`;
		}

		const uid = this.emlIndex[eml];
		const user = this.uidIndex[uid];

		const pwd = this.hashPassword(password, user.slt);
		if(pwd != user.pwd) {
			throw `Incorrect password.`;
		}

		return user;
	}

	update(email, password, data) {
		const eml = this.standardizeEmail(email);
		if(this.emlIndex[eml] == undefined) {
			throw `User ${eml} does not exist.`;
		}

		const uid = this.emlIndex[eml];
		const user = this.uidIndex[uid];

		const pwd = this.hashPassword(password, user.slt);
		if(pwd != user.pwd) {
			throw `Incorrect password.`;
		}

		const { newPassword } = data;
		if(newPassword) {
			const pwd = this.hashPassword(newPassword, user.slt);
			user.pwd = pwd;
		} 

		this.#saveUser(user);
		return user;
	}

	delete(email, password) {
		const eml = this.standardizeEmail(email);
		if(this.emlIndex[eml] == undefined) {
			throw `User ${eml} does not exist.`;
		}

		const uid = this.emlIndex[eml];
		const user = this.uidIndex[uid];

		const pwd = this.hashPassword(password, user.slt);
		if(pwd != user.pwd) {
			throw `Incorrect password.`;
		}

		this.uidIndex[uid] = undefined;
		this.emlIndex[eml] = undefined;
		
		const file = path.join(
			this.#userDb.dir,
			uid.substring(0, 2)
		);

		const data = fs.readFileSync(file);
		const users = JSON.parse(data);
		
		let idx = 0;
		for(idx = 0; idx < users.length; idx++) {
			if(users[idx].uid == user.uid) {
				users.splice(idx, 1);
				fs.writeFileSync(file, JSON.stringify(users));
				break;
			}
		}
	}

	standardizeEmail(email) {
		return email.trim().toLowerCase();
	}

	hashPassword(password, salt) {
		const hash = crypto.createHash("sha256");
		hash.update(password);
		hash.update(salt);
		return hash.digest("base64");
	}

	#saveUser(user) {
		const file = path.join(
			this.#userDb.dir,
			user.uid.substring(0, 2)
		);

		let users = [];
		if(fs.existsSync(file)) {
			const data = fs.readFileSync(file);
			users = JSON.parse(data);
		}

		let exists = false;
		for(let i = 0; i < users.length; i++) {
			if(users[i].uid == user.uid) {
				users[i] = user;
				exists = true;
				break;
			}
		}

		if(!exists) users.push(user);

		fs.writeFileSync(file, JSON.stringify(users));
	}
}