const express = require("express");
const mongoose = require("mongoose");
const passport = require("passport"); // authentication
const session = require('express-session') // session
const passportLocalMongoose = require("passport-local-mongoose"); // passport paketini otomatik ayarlıyor
const fs =require('fs');
const path = require('path')
const https = require('https');
const app = express();

var ipfsAPI = require('ipfs-api')
var multer  = require('multer');
const { hash } = require("bcrypt");
var upload = multer({ dest: 'uploads/' })
var ipfs = ipfsAPI('localhost', '5001', {protocol: 'http'})
var lastaccess = [];
var lastpinned = [];
var accesscounts = new Map();

const crypto = require("crypto");
const algorithm = "aes-256-ctr";
const serverSecretKey = "Juggernautdrowaxecentaurinvokers";
const iv = crypto.randomBytes(16);

var encrypt = function(data, secretKey) {
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);

    return {
        iv: iv.toString('hex'),
        content: encrypted.toString('binary')
    }
}

var decrypt = function(hash, secretKey) {
    const decipher = crypto.createDecipheriv(algorithm, secretKey, Buffer.from(hash.iv, 'hex'));
    const decrpyted = Buffer.concat([decipher.update(Buffer.from(hash.content, 'binary')), decipher.final()]);

    return decrpyted.toString();
};

var kencrypt = function(data, secretKey) {
    const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
    const encrypted = Buffer.concat([cipher.update(data), cipher.final()]);

    return {
        iv: iv.toString('hex'),
        content: encrypted.toString('hex')
    }
}

var kdecrypt = function(hash, secretKey) {
    const decipher = crypto.createDecipheriv(algorithm, secretKey, Buffer.from(hash.iv, 'hex'));
    const decrpyted = Buffer.concat([decipher.update(Buffer.from(hash.content, 'hex')), decipher.final()]);

    return decrpyted.toString();
};



app.use(express.json()); // body parser
app.use(express.urlencoded({ extended: true })); // body parser
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(session({
    secret: "sylvanasillidandrowrangertemplarassasinterrorbladejuggernautyurneroıotinydeathprophetnaturesprophetenigmatidehunter",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://localhost/kaandb', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  useFindAndModify: false,
  useCreateIndex: true
});

function hashinfo(filename, hash, date, size, status){
	this.filename = filename;
	this.hash = hash;
	this.date = date;
	this.size = size;
	this.status = status;
}

const userSchema = new mongoose.Schema ( {
    username: String,
    password: String,
});

const userHashSchema = new mongoose.Schema ( {
	username: String,
	hashinfoarr: [Object]

});

const userSecretSchema = new mongoose.Schema ({
	username: String,
	Secret: Object
});

userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);
const Hash = new mongoose.model("Userhashes", userHashSchema);
const Secret = new mongoose.model("UserKeys", userSecretSchema);

passport.use(User.createStrategy());
passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get('/pinner', function (req, res) {
	if(req.isAuthenticated()){
		res.sendFile(__dirname+'/page.html');
	}
	else{
		res.redirect("/");
	}
})

app.post('/hash', upload.single('upfile'), function (req, res, next) {
	if(req.isAuthenticated()){
		if(req.file){
			Secret.findOne({username: req.user.username}, function(err5, res5){
				if(err5){
					console.log(err5);
				}
				const userkey = kdecrypt({iv: res5.Secret.iv, content: res5.Secret.content.toString()}, serverSecretKey);
				if(req.body.encoption){
				var data = Buffer.alloc(req.file.size, fs.readFileSync(req.file.path, "binary"));
				var encrypteddata = encrypt(data, userkey);
				var final = Buffer.from(JSON.stringify(encrypteddata));
			}
			else{
				var final = Buffer.alloc(req.file.size, fs.readFileSync(req.file.path));
			}
			
		ipfs.add(final, { pinned: true },  function (err, file){
			if(err){
				console.log(err);
			}

			if(!lastpinned.includes(file[0].hash)){
				lastpinned.unshift(file[0].hash);
				if(lastpinned.length > 10){
					lastpinned.splice(9, lastpinned.length-10);
				}
			}
			Hash.findOne({username: req.user.username}, function(err2, result){
			
				if(result){
					var arr = result.hashinfoarr;
					existflag = false;
					for(let item of arr){
						if(item.hash == file[0].hash){
							existflag = true;
						}
					}
					if(existflag == false){
						arr.push(new hashinfo(req.file.originalname, file[0].hash, new Date(), file[0].size, "Self"));
						Hash.updateOne({username: req.user.username}, {hashinfoarr: arr}, function(err3){
							res.redirect("/mypins");
							if(err3){
								console.log(err3);
							}
						});
					}
					else{
						res.redirect("/mypins");
					}
					
				}
				else{
					var arr = [];
					arr.push(new hashinfo(req.file.originalname, file[0].hash, new Date(), file[0].size, "Self"));
					var userhashdata = new Hash({username: req.user.username, hashinfoarr: arr});
					userhashdata.save(function(err3){
						res.redirect("/mypins");
						if(err3){
							console.log(err3);
						}
					});
				}
			})
		
		})	// add and pin file to the local storage
			});
		}
		else{
			res.redirect("/pinner");
		}
	}
	else{
		res.redirect("/");
	}
	
	
  })

app.post('/hash2', function (req, res, next) {
   
	if(req.isAuthenticated()){
		const pinset = ipfs.pin.add(req.body.hash, { recursive: true }, function(err){
			if(err){
				res.send("Wrong hash!")
				res.end();
			}
			else{
				if(!lastpinned.includes(req.body.hash)){
					lastpinned.unshift(req.body.hash);
					if(lastpinned.length > 10){
						lastpinned.splice(9, lastpinned.length-10);
					}
				}
				Hash.findOne({username: req.user.username}, function(err2, result){
			
					if(result){
						var arr = result.hashinfoarr;
						existflag = false;
						for(let item of arr){
							if(item.hash == req.body.hash){
								existflag = true;
							}
						}
						if(existflag == false){
							arr.push(new hashinfo("Unknown", req.body.hash, new Date(), "Unknown", "Remote"));
							Hash.updateOne({username: req.user.username}, {hashinfoarr: arr}, function(err3){
								res.redirect("/mypins");
								if(err3){
									console.log(err3);
								}
							});
						}
						else{
							res.redirect("/mypins");
						}
						
					}
					else{
						var arr = [];
						arr.push(new hashinfo("Unknown", req.body.hash, new Date(), "Unknown", "Remote"));
						var userhashdata = new Hash({username: req.user.username, hashinfoarr: arr});
						userhashdata.save(function(err3){
							res.redirect("/mypins");
							if(err3){
								console.log(err3);
							}
						});
					}
				})
			}
		}) // pin by hash recursively
	}
	else{
		res.redirect("/");
	}
	
  })

app.post('/remove', async function (req, res, next) {
	if(req.isAuthenticated()){
		var testing = await Hash.find({});
		var otherhashash = false;
		for(var item of testing){
			var hasharr = item.hashinfoarr;
			for(var item2 of hasharr){
				if(item2.hash == req.body.hash && item.username != req.user.username && item2.status == "Self"){
					otherhashash = true;
				}
			}
		}
		if(otherhashash){
			Hash.findOne({username: req.user.username}, function(err, result){
					if(result){
						var arr = result.hashinfoarr;
						var flag = false;
						for(let i=0; i < arr.length; i++){
							if(arr[i].hash == req.body.hash){
								flag = true;
								arr.splice(i, 1);
								break;
							}
						}
						Hash.updateOne({username: req.user.username}, {hashinfoarr: arr}, function(err3){
							res.redirect("/mypins");
							if(err3){
								console.log(err3);
							}
						});	
					}
					else{
						res.redirect("/mypins");
					}
				})
		}
		else{
			const removedPinset = ipfs.pin.rm(req.body.hash, function(err){
			if(err){
				res.send("Not pinned or pinned indirectly");
				res.end();
			}
			else{
				if(lastaccess.includes(req.body.hash)){
					lastaccess.splice(lastaccess.indexOf(req.body.hash), 1);
				}
				if(lastpinned.includes(req.body.hash)){
					lastpinned.splice(lastpinned.indexOf(req.body.hash), 1);
				}
				accesscounts.delete(req.body.hash);
				Hash.findOne({username: req.user.username}, function(err, result){
					if(result){
						var arr = result.hashinfoarr;
						var flag = false;
						for(let i=0; i < arr.length; i++){
							if(arr[i].hash == req.body.hash){
								flag = true;
								arr.splice(i, 1);
								break;
							}
						}
						Hash.updateOne({username: req.user.username}, {hashinfoarr: arr}, function(err3){
							res.redirect("/mypins");
							if(err3){
								console.log(err3);
							}
						});	
					}
					else{
						res.redirect("/mypins");
					}
				})
			}
		})
		}
	}
	else{
		res.redirect("/");
	}

  }) // remove the recursive pin


app.get("/mypins", function(req, res){
	if(req.isAuthenticated()){
		Hash.findOne({username: req.user.username}, function(err, result){
			if(result){
				res.render("mypins", {userhashes: result.hashinfoarr});
			}
			else{
				var arr = [];
				res.render("mypins", {userhashes: arr});
			}
		})
	}
	else{
		res.redirect("/");
	}
})


app.post('/redirect', function(req, res, next){
	if(req.isAuthenticated()){
		if(accesscounts.has(req.body.hash2)){
			accesscounts.set(req.body.hash2, accesscounts.get(req.body.hash2) + 1 );
		}
		else{
			accesscounts.set(req.body.hash2, 1);
		}
		res.redirect('https://ipfs.io/ipfs/'+ req.body.hash2);
		if(!lastaccess.includes(req.body.hash2)){
			lastaccess.unshift(req.body.hash2);
			if(lastaccess.length > 10){
				lastaccess.splice(9, lastaccess.length-10);
			}
		}
		
		res.end();
	}
	else{
		res.redirect("/");
	}
	
}) // redirect to ipfs hash.

app.post("/decrypt", upload.single('upfile2'), function(req, res){
	if(req.isAuthenticated()){
		Secret.findOne({username: req.user.username}, function(err, result){
			if(err){
				console.log(err);
			}
			else{
				const userkey = kdecrypt({iv: result.Secret.iv, content: result.Secret.content.toString()}, serverSecretKey);
				var data = Buffer.alloc(req.file.size, fs.readFileSync(req.file.path));
				var temp = JSON.parse(data);
				var file = decrypt(temp, userkey);
				fs.writeFileSync("file", file, "binary");
				res.sendFile(__dirname+"/file");
			}
			res.end();
		});
	}
	else{
		res.redirect("/");
	}
	
});

app.get("/", function(req, res){
	if(req.isAuthenticated()){
		res.redirect("/pinner")
	}
	else{
		res.render("homepage");
	}
});


app.get("/login", function(req, res){
	if(req.isAuthenticated()){
		res.redirect("/pinner");
	}
	else{
		res.render("login");
	}
	
});

app.get("/logout", function(req, res){
	req.logout();
	res.redirect("/");
});

app.get("/register", function(req, res){
	if(req.isAuthenticated()){
		res.redirect("/pinner");
	}
	else{
		res.render("register");
	}
});

app.get("/accesscounts", function(req, res){
	if(req.isAuthenticated()){
		res.render("accesscounts", {userhashes: accesscounts});
	}
	else{
		res.redirect("/");
	}
});

app.get("/lastaccess", function(req, res){
	if(req.isAuthenticated()){
		res.render("lastaccess", {userhashes: lastaccess});
	}
	else{
		res.redirect("/");
	}
});

app.get("/lastpins", function(req, res){
	if(req.isAuthenticated()){
		res.render("lastpins", {userhashes: lastpinned});
	}
	else{
		res.redirect("/");
	}
});

app.post("/login", passport.authenticate("local", {successRedirect: "/", failureRedirect: "/login"}))

app.post("/register", function(req, res){

	User.register({username: req.body.username}, req.body.password, function(err, result){
		if(err){
			console.log(err);
			res.redirect("/register");
		}
		else{
			var key = crypto.randomBytes(16).toString('hex');
			var usersecretdata = new Secret({username: req.body.username, Secret: kencrypt(key, serverSecretKey)});
			usersecretdata.save(function(err2){
				if(err2){
					console.log(err2);
				}
				else{
					passport.authenticate("local")(req, res, function(){
						res.redirect("/");
			
					});
				}
			});
			
		}
	});
	
});


app.listen(65432, function(){
	console.log("ok");
});