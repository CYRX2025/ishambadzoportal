const http = require('http');
const fs = require('fs');
const path = require('path');
const root = __dirname;
const PORT = process.env.PORT || 8080;
const MIME = { '.html':'text/html; charset=utf-8', '.js':'text/javascript', '.css':'text/css', '.png':'image/png', '.svg':'image/svg+xml', '.json':'application/json' };
http.createServer((req,res)=>{
  let p = decodeURIComponent(req.url.split('?')[0]);
  if(req.method === 'POST'){ req.resume(); }  /* preview only: swallow hotspot form posts */
  if(p === '/') p = '/login.html';
  p = path.normalize(p);
  if(p.includes('..')){ res.writeHead(400, {'Content-Type':'text/plain; charset=utf-8'}); res.end('400: bad path'); return; }
  const file = path.join(root, p);
  if(!fs.existsSync(file) || !fs.statSync(file).isFile()){
    res.writeHead(404, {'Content-Type':'text/plain; charset=utf-8'});
    res.end('404: ' + p);
    return;
  }
  const data = fs.readFileSync(file);
  res.writeHead(200, {'Content-Type': MIME[path.extname(file).toLowerCase()] || 'application/octet-stream'});
  res.end(data);
}).listen(PORT, ()=> console.log('serving http://localhost:' + PORT));