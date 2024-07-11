import express from 'express';
import bodyParser from 'body-parser';
import cookieParser from 'cookie-parser';

import jwt from 'jsonwebtoken';
const { sign, verify } = jwt;

import nconf from 'nconf';
import { createTrip } from '2ch-trip';
import { lookup } from 'dnsbl';

import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const VERSION = '1.1.0';
const app = express();
const colors = [
  '#e1d9fa',
  '#ff1638',
  '#eafc5b',
  '#6cffcd',
  '#4287f5',
  '#ff9932',
  '#aa42ff',
];
let onlineUsers = {};

console.log('Loading configuration');
nconf.file({ 'file': 'config.json' });
const port = nconf.get('port');
const staff = nconf.get('staff');
const nameless = nconf.get('nameless');
const capcode = nconf.get('capcode');
const secretKey = nconf.get('secretKey');
const emotes = nconf.get('emotes');
const bannedMsg = nconf.get('bannedMsg');
const badWordMsg = nconf.get('badWordMsg');
const localeString = nconf.get('localeString');
const maxInactivityMinutes = parseInt(nconf.get('maxInactivityMinutes'));

function reloadBanLists() {
  try {
    const ipsPath = path.join(__dirname, '../banned-ips.txt');
    const wordsPath = path.join(__dirname, '../banned-words.txt');

    const bannedIps = fs
      .readFileSync(ipsPath, 'utf8')
      .trim()
      .split('\n');
    const bannedWords = fs
      .readFileSync(wordsPath, 'utf8')
      .trim()
      .split('\n')
      .filter(word => word.trim().length > 0);

    return {
      bannedIps: bannedIps,
      bannedWords: bannedWords
    };
  } catch (err) {
    console.error('Error: unable to load ban lists: ', err);
    return {
      bannedIps: [],
      bannedWords: []
    };
  }
}

function getChatLog(size) {
  try {
    const filePath = path.join(__dirname, '../public/chatlog.txt');
    if (!fs.existsSync(filePath))
      fs.writeFileSync(filePath, '', 'utf8');

    return fs.readFileSync(filePath, 'utf8').split('\n').slice(0, size);
  } catch(err) {
    console.error('Unable to read messages:', err);
    return [];
  }
}

function addMessage(message) {
  try {
    const filePath = path.join(__dirname, '../public/chatlog.txt');
    if (!fs.existsSync(filePath))
      fs.writeFileSync(filePath, '', 'utf8');

    const oldLog = fs.readFileSync(filePath, 'utf8');
    const date = new Date().toLocaleString(localeString, { timeZone: 'UTC' });

    const msgStyle = message.color < 7 ?
    `style="color: ${colors[message.color]};"` :
    'class="rainbow"';

    const formattedMessage =
      '<span ${c} data-timestamp="${ti}">★ <b>${u}</b>${t} > ${m} <span class="gray">(${d})</span></span>\n'
      .replace('${c}', msgStyle)
      .replace('${ti}', message.timestamp)
      .replace('${u}', message.username)
      .replace('${t}', message.tripcode)
      .replace('${m}', message.text)
      .replace('${d}', date);

    const newContent = formattedMessage + oldLog;

    const lines = newContent.trim().split('\n').slice(0, 500);
    const updatedContent = lines.join('\n');

    fs.writeFileSync(filePath, updatedContent, 'utf8');
  } catch (err) {
    console.error('Error appending message:', err);
  }
}

function deleteMessage(timestamp) {
  try {
    const filePath = path.join(__dirname, '../public/chatlog.txt');
    const htmlContent = fs.readFileSync(filePath, 'utf8');
    const regex = new RegExp(`<span\\s+[^>]*data-timestamp="${timestamp}"[^>]*>`, 'g');

    const lines = htmlContent.trim().split('\n').slice(0, 500);
    const newContent = lines
      .filter(line => !regex.test(line))
      .join('\n');

    fs.writeFileSync(filePath, newContent, 'utf8');
  } catch (err) {
    console.error(`Error deleting message ${timestamp}:`, err);
  }
}

function deleteAllMessages() {
  try {
    const filePath = path.join(__dirname, '../public/chatlog.txt');
    fs.truncateSync(filePath, 0);
    fs.writeFileSync(filePath, '', 'utf8');
  } catch (err) {
    console.error(`Error clearing messages ${timestamp}:`, err);
  }
}

function banIp(ip) {
  try {
    const bannedIpsPath = path.join(__dirname, '../banned-ips.txt');
    const oldBannedIps = fs.readFileSync(bannedIpsPath, 'utf8').trim().split('\n');

    if (oldBannedIps.includes(ip))
      return;

    const newBannedIps = [...oldBannedIps, ip].filter(i => i.length > 0);
    fs.writeFileSync(bannedIpsPath, newBannedIps.join('\n'), 'utf8');
    bannedIps = reloadBanLists().bannedIps;
  } catch (err) {
    console.error('Error banning IP:', err);
  }
}

function checkUserActivity() {
  const onlineIps = Object.keys(onlineUsers);
  const now = Date.now();
  const maxInactivityTime = maxInactivityMinutes * 60 * 1000;
  for (let i = 0; i < onlineIps.length; i++)
    if (now - onlineUsers[onlineIps[i]].lastActivity > maxInactivityTime) {
      const username = onlineUsers[onlineIps[i]].username;
      console.log(`${username} (${onlineIps[i]}) removed from online list (timed out)`);
      delete onlineUsers[onlineIps[i]];
    }
}

let { bannedIps, bannedWords } = reloadBanLists();

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));
app.use(bodyParser.urlencoded({ extended: true, limit: '2mb' }));
app.use(cookieParser());

app.use(express.static(path.join(__dirname, '..', 'public')));
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    'default-src \'self\' https://saki.ichoria.org \'unsafe-inline\'; img-src \'self\' data: https:; frame-ancestors \'self\';'
  );
  res.setHeader('Referrer-Policy', 'strict-origin');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});
app.use((req, res, next) => {
  const token = req.cookies.jwt;

  req.isLoggedIn = false;
  req.user = null;

  if (!token)
    return next();

  jwt.verify(token, secretKey, (err, user) => {
    if (err)
      return next();
    req.isLoggedIn = true;
    req.user = user;
    next();
  });
});

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/join', (req, res) => {
  if (req.isLoggedIn)
    return res.redirect('/compose');
  res.render('form-join');
});

app.get('/compose', (req, res) => {
  if (!req.isLoggedIn)
    return res.redirect('/join');

  const msgStyle = req.user.color < 7 ?
    `style="color: ${colors[req.user.color]};"` :
    'class="rainbow"';

  res.render('form-compose', {
    username: req.user.username,
    tripcode: req.user.tripcode,
    msgStyle
  });
});

app.get('/chat', (req, res) => {
  const chatLog = getChatLog(100);
  const isLoggedIn = req.isLoggedIn;
  const user = req.user ?? null;

  res.render('chat', {
    chatLog,
    colors,
    onlineUsers,
    isLoggedIn,
    user
  });
});

app.get('/info', (req, res) => {
  res.render('info', {
    emotes
  });
});

app.get('/admin/del', (req, res) => {
  if (!req.isLoggedIn || !req.user.isAdmin)
    return res.status(404).render('not-found');
  
  const timestamp = parseInt(req.query.timestamp) ?? 0;
  deleteMessage(timestamp);
  console.log(`Admin ${req.user.username} deleted message ${timestamp}`);

  res.redirect('/chat');
});

app.get('/admin/ban', (req, res) => {
  if (!req.isLoggedIn || !req.user.isAdmin)
    return res.status(404).render('not-found');
  
  const timestamp = parseInt(req.query.timestamp) ?? 0;
  deleteMessage(timestamp);
  console.log(`Admin ${req.user.username} deleted message ${timestamp}`);

  const onlineIps = Object.keys(onlineUsers);
  for(let i = 0; i < onlineIps.length; i++)
    if (onlineUsers[onlineIps[i]].messages.includes(timestamp)) {
      banIp(onlineIps[i]);
      console.log(`Admin ${req.user.username} banned IP ${onlineIps[i]}`);
      return res.render('result', {
        url: '/chat',
        refresh: '2',
        message: `La IP ${onlineIps[i]} fue baneada`
      });
    }
  
  res.render('result', {
    url: '/chat',
    refresh: '2',
    message: 'Usuario expirado; es necesario banear desde el servidor' +
    ' (el mensaje fue borrado)'
  });
});

app.get('/admin/truncate', (req, res) => {
  if (!req.isLoggedIn || !req.user.isAdmin)
    return res.status(404).render('not-found');
  
  deleteAllMessages();
  console.log(`Admin ${req.user.username} cleared the messages`);

  res.redirect('/chat');
});

app.get('/action/logout', (req, res) => {
  if (!req.isLoggedIn)
    return res.redirect('/join');
  const ip = req.headers['x-forwarded-for'] ?
    req.headers['x-forwarded-for'].split(',')[0] :
    req.socket.remoteAddress;

  console.log(`${req.user.username} left the chat`);
  if (onlineUsers[ip])
    delete onlineUsers[ip];
  res.clearCookie('jwt');
  req.isLoggedIn = false;
  req.user = null;
  res.redirect('/join');
});

app.post('/action/login', async (req, res) => {
  if (req.isLoggedIn)
    return res.redirect('/compose');

  const formData = req.body;
  const ip = req.headers['x-forwarded-for'] ?
    req.headers['x-forwarded-for'].split(',')[0] :
    req.socket.remoteAddress;

  if (formData.username ||
    formData.password ||
    await lookup(ip, 'all.s5h.net'))
      return res.redirect('/join');
    
  if (bannedIps.includes(ip)) {
    console.log(`Banned address ${ip} rejected`);
    return res.render('result', {
      url: '/join',
      refresh: '6',
      message: bannedMsg.replace('${ip}', ip)
    });
  }

  const color = parseInt(formData.color) ?? 0;
  const rawCredentials = formData.nomen ?? nameless;
  const tripcodeMatch = rawCredentials.match(/(.*?)(#|##)([^#]*)$/);

  const rawUsername = tripcodeMatch ? tripcodeMatch[1] : rawCredentials;
  const username = !(rawUsername.trim().length) ?
    nameless :
    rawUsername;
  const password = tripcodeMatch ? tripcodeMatch[3] : '';
  const tripcode = password.length ? (staff[username] && staff[username] === password ?
      capcode :
      createTrip(tripcodeMatch[2] + password)) :
    '';

  const user = {
    username: username,
    tripcode: tripcode,
    isAdmin: tripcode === capcode,
    color: color
  };

  const accessToken = jwt.sign(user, secretKey, {
    expiresIn: user.isAdmin ? '2h' : '24h'
  });
  res.cookie('jwt', accessToken, {
    maxAge: (user.isAdmin ? 2 : 24) * 60 * 60 * 1000,
    sameSite: (user.isAdmin ? 'strict' : 'lax')
  });
  onlineUsers[ip] = { ...user, messages: [], lastActivity: Date.now() };

  console.log(`${user.username} (${ip}) joined the chat`);
  res.redirect('/compose');
});

app.post('/action/send', async (req, res) => {
  if (!req.isLoggedIn)
    return res.redirect('/join');

  const formData = req.body;
  const ip = req.headers['x-forwarded-for'] ?
    req.headers['x-forwarded-for'].split(',')[0] :
    req.socket.remoteAddress;

  if (formData.message ||
    await lookup(ip, 'all.s5h.net')) {
      return res.redirect('/chat');
  }
  if (bannedIps.includes(ip)) {
    console.log(`Banned address ${ip} rejected`);
    return res.render('result', {
      url: '/chat',
      refresh: '6',
      message: bannedMsg.replace('${ip}', ip)
    });
  }

  const rawMessage = formData.epistula ?? '';
  for (let i = 0; i < bannedWords.length; i++)
    if (rawMessage.includes(bannedWords[i])) {
      console.log(`Message with banned word from ${req.user.username} (${ip}) rejected`);
      return res.render('result', {
        url: '/chat',
        refresh: '2',
        message: badWordMsg
      });
    }

  const timestamp = Date.now();
  const oldMessages = onlineUsers[ip] && onlineUsers[ip].hasOwnProperty('messages') ?
   onlineUsers[ip].messages : 
   [];
  const newMessages = [ ...oldMessages, timestamp ];
  onlineUsers[ip] = { ...req.user, lastActivity: timestamp, messages: newMessages };

  if (!rawMessage.trim().length)
    return res.redirect('/chat');

  const msgText = rawMessage
    .replace(/\n/g, '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/(:\w+:)/g, match => {
      const emoteName = match.slice(1, -1);
      const emoteFile = emotes[emoteName];
      if (emoteFile)
        return `<img class="emote" src="/img/emotes/${emoteFile}" alt="${emoteName}" load="lazy">`;
      return match;
    })
    .replace(/\*\*(.*?)\*\*/g, '<b>$1</b>')
    .replace(/__(.*?)__/g, '<em>$1</em>')
    .replace(/~~(.*?)~~/g, '<span class="spoiler">$1</span>')
    .replace(/(https?:\/\/\S+)/g, '<a href="$1" target="_blank">$1</a>');
  
  const message = {
    username: req.user.username
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;'),
    tripcode: req.user.tripcode,
    color: req.user.color,
    text: msgText,
    timestamp: timestamp
  };

  addMessage(message);
  console.log(`${message.username}${message.tripcode} > ${rawMessage}`);
  res.redirect('/chat');
});

setInterval(checkUserActivity, 60000);

app.use((req, res, next) => {
  res.status(404).render('not-found');
});

app.listen(port, () => {
  console.log(`rhizomechat listening on http://localhost:${port}`);
});
