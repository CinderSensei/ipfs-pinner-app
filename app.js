const fs =require('fs');
const path = require('path')
const https = require('https');
const express = require('express')
const bodyParser = require("body-parser");
/*const IPFS = require('ipfs')
const OrbitDB = require('orbit-db')*/

/*Currently api address is ip4/127.0.0.1/portno, you can change it to ip4/0.0.0.0/portno idk yet still uploading tho */


const app = express()
var ipfsAPI = require('ipfs-api')
var multer  = require('multer')
var upload = multer({ dest: 'uploads/' })
var ipfs = ipfsAPI('localhost', '5001', {protocol: 'http'}) // public ip port yönlendirme

app.use(bodyParser.urlencoded({extended:true}));
	
	/*async function main() {
	  const ipfs2 = await IPFS.create();
	  const orbitdb = await OrbitDB.createInstance(ipfs2);
	  const db = await orbitdb.docs('opews-db-test1');
	  const address = db.address;
	}
	// cant spawn node in code.
	main()*/ 

	
    app.get('/', function (req, res) {
        res.sendFile(__dirname+'/src/front/page.html');
    })

    app.post('/hash', upload.single('upfile'), function (req, res, next) {
       
        var data = Buffer.alloc(req.file.size, fs.readFileSync(req.file.path));
        ipfs.add(data, { pinned: true },  function (err, file){
            if(err){
                console.log(err);
            }
            console.log(file);
            res.send("Hash is: "+ file[0].hash);
            res.end();
     
        }) // add and pin file to the local storage
        
      })

    app.post('/hash2', function (req, res, next) {
       
   
        const pinset = ipfs.pin.add(req.body.hash, { recursive: true }, function(err){
            if(err){
                res.send("Wrong hash!")
            }
            res.send(req.body.hash + " successfully pinned!");
     		res.end();
        }) // pin by hash recursively
        
      })

    app.post('/remove', function (req, res, next) {

      	const removedPinset = ipfs.pin.rm(req.body.hash, function(err){
      		if(err){
      			res.send("Not pinned or pinned indirectly");
      		}
	  		res.send(req.body.hash + " is unpinned!");
	  		res.end();
	  	})

      }) // remove the recursive pin

 /* app.post('/list', function (req, res) {

       query from the database which includes cids, filenames, size, pinned times, user id etc.
       also use a table for unpinned files

      })*/ // List the current pins of the user dont use ipfs.pin.ls it will show whole repo. Get it with query from your future database.


    app.post('/redirect', function(req, res, next){
        res.redirect('https://ipfs.io/ipfs/'+ req.body.hash2);
        res.end();
    }) // redirect to ipfs hash. Not my spec but whatever. Extra spec is good.
 
app.listen(3000)