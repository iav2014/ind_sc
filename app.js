/*
* goal: http(s) token server, generate token server only for a whitelist source.
* tenant: inditex security solutions
* ttl token server + whitelist + antiddos attack
* author: (c) 19/10/2018 Nacho Ariza
* MIT license
*/
'use strict';
let express = require('express');
let cluster = require('cluster');
let https = require('https');
let http = require('http');
let bodyParser = require('body-parser');
let morgan = require('morgan');
var RateLimit = require('express-rate-limit');


let fs = require('fs');
let app = express();
let cnf = {
	http_port: process.env.PORT || 3000,
	https_port: process.env.PORT || 3443,
	environment: process.env.ENV || 'develop',
};

// ddos middleware
var ddos_limiter = new RateLimit({
	windowMs:   1000, // example: 15 minutes  15*60*1000
	max: 100, // limit each IP to 100 requests per windowMs
	delayMs: 0, // disable delaying - full speed until the max limit is reached
	message:'ddos detected!'
});

// time ms express middleware
let theHTTPLog = morgan(':remote-addr - :method :url HTTP/:http-version :status :res[content-length] - :response-time ms', {
	'stream': {
		write: function (str) {
			console.log(str);
		}
	}
});
let key = fs.readFileSync('./cert/server.key'); // your server.key && pem files
let cert = fs.readFileSync('./cert/server.pem')
let https_options = {
	key: key,
	cert: cert
};
// express whitelist middleware
let allowedOrigins = 'http://127.0.0.1:8020,http://localhost:3000,https://localhost:3443,http://localhost:9000';

// encoder symmetric xor based example!
let encoder = (str) => {
	let encoded = '', l = str.length;
	for (let i = 0; i < l; i++) {
		let a = str.charCodeAt(i);
		let b = a ^ 377829123;
		encoded = encoded + String.fromCharCode(b);
	}
	return encoded;
};
let start = (app) => {
		//  apply to all requests
		app.use(ddos_limiter); // middleware anti ddos
		app.use(bodyParser.urlencoded({
			extended: true
		}));
		app.use(bodyParser.json({limit: '5mb'}));
		
		app.use(function (req, res, next) {
			res.setHeader('Access-Control-Allow-Origin', '*');
			next();
		});
		app.use(theHTTPLog); // middleware morgan ms crono
		
	// middleware whitelist
		app.use(function (req, res, next) {
			// this is the white list. Test if works from internet...
			let origin = req.headers.origin ? req.headers.origin : req.headers.host;
			if (allowedOrigins.indexOf(origin) > -1) {
				res.setHeader('Access-Control-Allow-Origin', origin);
				next();
			} else {
				res.sendStatus(401);
			}
		});
		
		
		// routes
		// token method: generate valid token...
		// you save at mongodb all generated tokens to check later ...
		app.post('/token', (req, res, next) => {
			req.query = req.body;
			try {
				let offset = parseInt(req.query.keepalive || 60);
				let token = new Date() / 1000 + offset;
				let json = {token: token, keepalive: offset}
				res.send(encoder(JSON.stringify(json)));
			} catch (err) {
				console.error(err);
				res.sendStatus(404);
			}
		});
		// check token, returns 200 or 404 if token is valid || if exist in database ...
		app.post('/check', (req, res, next) => {
			req.query = req.body;
			try {
				let json = JSON.parse(encoder(req.query.token));
				if (json.token || json.keepalive) {
					res.sendStatus(200);
				} else {
					res.sendStatus(401);
				}
			} catch (err) {
				res.sendStatus(401);
			}
		});
		app.get('/check', (req, res, next) => {
			req.query = req.body;
			try {
				let json = JSON.parse(encoder(req.query.token));
				if (json.token || json.keepalive) {
					res.sendStatus(200);
				} else {
					res.sendStatus(401);
				}
			} catch (err) {
				res.sendStatus(401);
			}
		});
		https.createServer(https_options, app).listen(cnf.https_port).on('error', (err) => {
			if (err) {
				console.error(err);
				process.exit(1);
			}
		}).on('listening', () => {
			console.log(process.pid + ' - https listening on port:' + cnf.https_port);
		});
		http.createServer(app).listen(cnf.http_port).on('error', (err) => {
			if (err) {
				lconsole.error(err);
				process.exit(1);
			}
		}).on('listening', () => {
			console.log(process.pid + ' - http listening on port:' + cnf.http_port);
		});
	}
;

let startCluster = (app) => {
	if (!cluster.isMaster) {
		start(app);
	}
	else {
		console.log('config  =>');
		console.log(cnf);
		let threads = require('os').cpus().length;
		while (threads--) cluster.fork();
		cluster.on('death', (worker) => {
			cluster.fork();
			console.log('Process died and restarted, pid:', worker.pid);
		});
	}
};

startCluster(app);

