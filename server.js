const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const AdmZip = require('adm-zip');
const bcrypt = require('bcryptjs');

const app = express();
const storage = multer.memoryStorage();
const upload = multer({ storage: storage });

// Ensure directories exist
const domainsDir = path.join(__dirname, 'domains');
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(domainsDir)) fs.mkdirSync(domainsDir, { recursive: true });
if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

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
    saveData();
  }
  next();
});

// File system storage functions
function saveData() {
  try {
    fs.writeFileSync(path.join(dataDir, 'users.json'), JSON.stringify(users));
    fs.writeFileSync(path.join(dataDir, 'sites.json'), JSON.stringify(sites));
    fs.writeFileSync(path.join(dataDir, 'analytics.json'), JSON.stringify(analytics));
  } catch (error) {
    console.error('Error saving data:', error);
  }
}

function loadData() {
  try {
    if (fs.existsSync(path.join(dataDir, 'users.json'))) {
      users = JSON.parse(fs.readFileSync(path.join(dataDir, 'users.json')));
    }
    if (fs.existsSync(path.join(dataDir, 'sites.json'))) {
      sites = JSON.parse(fs.readFileSync(path.join(dataDir, 'sites.json')));
    }
    if (fs.existsSync(path.join(dataDir, 'analytics.json'))) {
      analytics = JSON.parse(fs.readFileSync(path.join(dataDir, 'analytics.json')));
    }
  } catch (error) {
    console.log('No existing data found, starting fresh');
  }
}

function generateSiteId() {
  return Math.random().toString(36).substring(2, 10) + Math.random().toString(36).substring(2, 10);
}

// Load data on startup
loadData();

// API Routes
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
  
  const siteId = generateSiteId();
  const domainDir = path.join(domainsDir, siteId);
  fs.mkdirSync(domainDir, { recursive: true });
  
  // Save uploaded files to file system
  req.files.forEach(file => {
    if (file.fieldname === 'zip') {
      const zip = new AdmZip(file.buffer);
      zip.getEntries().forEach(entry => {
        if (!entry.isDirectory) {
          const filePath = path.join(domainDir, entry.entryName);
          const dir = path.dirname(filePath);
          if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
          }
          fs.writeFileSync(filePath, zip.readFile(entry));
        }
      });
    } else {
      const filePath = path.join(domainDir, file.originalname);
      fs.writeFileSync(filePath, file.buffer);
    }
  });
  
  sites[domain] = { 
    owner: email, 
    siteId,
    created: new Date() 
  };
  
  saveData();
  res.json({ success: true, token: email, siteId, domain });
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
  if (!sites[domain] || sites[domain].owner !== req.user) {
    return res.status(403).json({ error: 'Not your site' });
  }
  
  const siteId = sites[domain].siteId;
  const domainDir = path.join(domainsDir, siteId);
  
  // Clear existing files
  if (fs.existsSync(domainDir)) {
    fs.rmSync(domainDir, { recursive: true });
    fs.mkdirSync(domainDir, { recursive: true });
  }
  
  // Save new files
  req.files.forEach(file => {
    if (file.fieldname === 'zip') {
      const zip = new AdmZip(file.buffer);
      zip.getEntries().forEach(entry => {
        if (!entry.isDirectory) {
          const filePath = path.join(domainDir, entry.entryName);
          const dir = path.dirname(filePath);
          if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
          }
          fs.writeFileSync(filePath, zip.readFile(entry));
        }
      });
    } else {
      const filePath = path.join(domainDir, file.originalname);
      fs.writeFileSync(filePath, file.buffer);
    }
  });
  
  sites[domain].updated = new Date();
  saveData();
  res.json({ success: true });
});

app.get('/api/analytics/:domain', requireAuth, (req, res) => {
  const domain = req.params.domain;
  if (!sites[domain] || sites[domain].owner !== req.user) {
    return res.status(403).json({ error: 'Not your site' });
  }
  res.json({ views: analytics[domain] || 0 });
});

app.get('/api/my-sites', requireAuth, (req, res) => {
  const userSites = users[req.user].domains.map(domain => ({
    domain,
    siteId: sites[domain].siteId,
    views: analytics[domain] || 0,
    created: sites[domain].created
  }));
  res.json({ sites: userSites });
});

// Domain file serving
app.get('/domains/:siteId/*', (req, res) => {
  const siteId = req.params.siteId;
  const filePath = req.params[0] || 'index.html';
  const fullPath = path.join(domainsDir, siteId, filePath);
  
  if (fs.existsSync(fullPath) && !fs.statSync(fullPath).isDirectory()) {
    return res.sendFile(fullPath);
  } else {
    const indexPath = path.join(domainsDir, siteId, 'index.html');
    if (fs.existsSync(indexPath)) {
      return res.sendFile(indexPath);
    } else {
      return res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head><title>404</title></head>
        <body>
          <h1>😿 404 - File not found</h1>
          <p><a href="#" onclick="window.parent.postMessage('navigate:register.cats', '*')">Create a site</a></p>
        </body>
        </html>
      `);
    }
  }
});

// Static pages
app.get('/register.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'register.html'));
});

app.get('/dashboard.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Main routing
app.get('*', (req, res) => {
  const host = req.headers.host;
  const queryDomain = req.query.domain;
  
  // Handle ?domain= queries - redirect to clean URLs
  if (queryDomain && queryDomain.endsWith('.cats')) {
    if (sites[queryDomain]) {
      return res.redirect(`/domains/${sites[queryDomain].siteId}/`);
    } else {
      return res.status(404).send(`
        <!DOCTYPE html>
        <html>
        <head><title>404</title></head>
        <body>
          <h1>😿 404 - ${queryDomain} not found</h1>
          <p><a href="#" onclick="window.parent.postMessage('navigate:register.cats', '*')">Register it now!</a></p>
        </body>
        </html>
      `);
    }
  }
  
  if (host === 'register.cats') {
    return res.sendFile(path.join(__dirname, 'public', 'register.html'));
  }
  
  if (host === 'dashboard.cats') {
    return res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
  }
  
  if (host && host.endsWith('.cats')) {
    if (sites[host]) {
      return res.redirect(`/domains/${sites[host].siteId}/`);
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