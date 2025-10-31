const express = require('express');
const multer = require('multer');
const path = require('path');
const AdmZip = require('adm-zip');
const bcrypt = require('bcryptjs');

const app = express();
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

let users = {};
let sites = {};
let analytics = {};

app.use(express.json());
app.use(express.static('public'));

function requireAuth(req, res, next) {
  const token = req.headers.authorization;
  if (token && users[token]) {
    req.user = token;
    next();
  } else {
    res.status(401).json({ error: 'Login required' });
  }
}

app.use((req, res, next) => {
  const host = req.headers.host;
  if (host && host.endsWith('.cats') && sites[host]) {
    analytics[host] = (analytics[host] || 0) + 1;
  }
  next();
});

app.post('/api/signup', upload.any(), async (req, res) => {
  const { email, password, domain } = req.body;
  
  if (users[email]) {
    return res.json({ success: false, error: 'Email already exists' });
  }
  if (sites[domain]) {
    return res.json({ success: false, error: 'Domain taken' });
  }
  
  const hashedPassword = await bcrypt.hash(password, 10);
  users[email] = { password: hashedPassword, domains: [domain] };
  
  const files = {};
  req.files.forEach(file => {
    if (file.fieldname === 'zip') {
      const zip = new AdmZip(file.buffer);
      zip.getEntries().forEach(entry => {
        if (!entry.isDirectory) {
          files[entry.entryName] = zip.readFile(entry).toString();
        }
      });
    } else {
      files[file.originalname] = file.buffer.toString();
    }
  });
  
  sites[domain] = { owner: email, files, created: new Date() };
  res.json({ success: true, token: email });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = users[email];
  
  if (user && await bcrypt.compare(password, user.password)) {
    res.json({ success: true, token: email, domains: user.domains });
  } else {
    res.json({ success: false, error: 'Invalid credentials' });
  }
});

app.post('/api/update-site', requireAuth, upload.any(), (req, res) => {
  const { domain } = req.body;
  if (sites[domain].owner !== req.user) {
    return res.status(403).json({ error: 'Not your site' });
  }
  
  const files = {};
  req.files.forEach(file => {
    if (file.fieldname === 'zip') {
      const zip = new AdmZip(file.buffer);
      zip.getEntries().forEach(entry => {
        if (!entry.isDirectory) {
          files[entry.entryName] = zip.readFile(entry).toString();
        }
      });
    } else {
      files[file.originalname] = file.buffer.toString();
    }
  });
  
  sites[domain].files = files;
  sites[domain].updated = new Date();
  res.json({ success: true });
});

app.get('/api/analytics/:domain', requireAuth, (req, res) => {
  const domain = req.params.domain;
  if (sites[domain].owner !== req.user) {
    return res.status(403).json({ error: 'Not your site' });
  }
  res.json({ views: analytics[domain] || 0 });
});

app.get('/api/my-sites', requireAuth, (req, res) => {
  const userSites = users[req.user].domains.map(domain => ({
    domain,
    views: analytics[domain] || 0,
    created: sites[domain].created
  }));
  res.json({ sites: userSites });
});

app.get('/register.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('*', (req, res) => {
  const host = req.headers.host;
  const file = req.path.substring(1) || 'index.html';
  
  if (host && host.endsWith('.cats')) {
    if (sites[host] && sites[host].files[file]) {
      return res.send(sites[host].files[file]);
    } else if (sites[host] && sites[host].files['index.html']) {
      return res.send(sites[host].files['index.html']);
    } else {
      return res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>404 - Site Not Found</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; background: #fff5f5; text-align: center; }
                .container { max-width: 600px; margin: 0 auto; }
                h1 { color: #ff6b81; font-size: 48px; margin: 20px 0; }
                .cat { font-size: 80px; margin: 20px 0; }
                .domain { background: #ff6b81; color: white; padding: 5px 10px; border-radius: 5px; }
                a { color: #ff6b81; text-decoration: none; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="cat">😿</div>
                <h1>404</h1>
                <h2>This .cats site doesn't exist yet!</h2>
                <p>The domain <span class="domain">${host}</span> isn't registered.</p>
                <p>Visit <a href="#" onclick="window.parent.postMessage('navigate:register.cats', '*')">register.cats</a> to claim it!</p>
            </div>
        </body>
        </html>
      `);
    }
  }
  
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🐾 PawNetwork running on port ${PORT}`));
